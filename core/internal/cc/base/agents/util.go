package agents

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SendCmd send command to agent
var SendCmd = func(cmd, cmd_id string, a *def.Emp3r0rAgent) error {
	if a == nil {
		return errors.New("SendCmd: agent not found")
	}

	var cmdData def.MsgTunData

	// add UUID to each command for tracking
	if cmd_id == "" {
		cmd_id = uuid.New().String()
	}

	// parse command
	cmdSlice := util.ParseCmd(cmd)
	cmdData.CmdSlice = cmdSlice
	cmdData.Tag = a.Tag
	cmdData.CmdID = cmd_id

	// timestamp
	cmdData.Time = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")

	return SendMessageToAgent(&cmdData, a)
}

// SendCmdToCurrentAgent send a command to currently selected agent
func SendCmdToCurrentAgent(cmd, cmd_id string) error {
	// target
	target := MustGetActiveAgent()
	if target == nil {
		return fmt.Errorf("you have to select a target first")
	}

	// send cmd
	return SendCmd(cmd, cmd_id, target)
}

// MustGetActiveAgent check if current target is set and alive
func MustGetActiveAgent() *def.Emp3r0rAgent {
	// find target
	if live.ActiveAgent == nil {
		logging.Debugf("Validate active target: target does not exist")
		return nil
	}

	// find target in live.AgentList
	for _, agent := range live.AgentList {
		if live.ActiveAgent.Tag == agent.Tag {
			return agent
		}
	}

	return nil
}
