package agents

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SendCmd send command to agent
var SendCmd = func(cmd, job_id string, a *def.Emp3r0rAgent) error {
	if a == nil {
		return fmt.Errorf("SendCmd: agent is nil")
	}

	var cmdData def.MsgTunData
	// if cmd_id is empty, generate a new one
	if job_id == "" {
		job_id = uuid.New().String()
	}

	// parse command
	cmdSlice := util.ParseCmd(cmd)
	cmdData.CmdSlice = cmdSlice
	cmdData.Tag = a.Tag
	cmdData.JobID = job_id

	// timestamp
	cmdData.Time = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")

	return SendMessageToAgent(&cmdData, a)
}

// SendCmdToCurrentAgent sends a command to the currently active agent
func SendCmdToCurrentAgent(cmd, job_id string) error {
	target := live.ActiveAgent
	if target == nil {
		return fmt.Errorf("SendCmdToCurrentAgent: no active agent")
	}
	return SendCmd(cmd, job_id, target)
}

// SanitizeAgentData cleans all string fields in Emp3r0rAgent to prevent terminal injection
func SanitizeAgentData(a *def.Emp3r0rAgent) {
	util.SanitizeAgentMetadata(a)
}

// MustGetActiveAgent check if current target is set and alive
func MustGetActiveAgent() *def.Emp3r0rAgent {
	// find target
	if live.ActiveAgent == nil {
		logging.Debugf("Validate active target: target does not exist")
		return nil
	}

	// find target in live.AgentList
	var fresh *def.Emp3r0rAgent
	live.AgentList.Range(func(_, value any) bool {
		agent, ok := value.(*def.Emp3r0rAgent)
		if ok && agent != nil && live.ActiveAgent.Tag == agent.Tag {
			fresh = agent
			return false // stop iteration
		}
		return true
	})

	return fresh
}
