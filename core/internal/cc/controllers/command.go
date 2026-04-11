package controllers

import (
	"fmt"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

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

	// Record command time immediately
	now := time.Now()
	live.CmdTime.Store(jobID, now.Format("2006-01-02 15:04:05.999999999 -0700 MST"))
	if agent := agents.GetAgentByTag(agentTag); agent != nil {
		agent.LastSeen = now
	}
	if live.ActiveAgent != nil && live.ActiveAgent.Tag == agentTag {
		live.ActiveAgent.LastSeen = now
	}

	// Send command asynchronously to avoid blocking
	go func() {
		err := client.SendCommand(operation)
		if err != nil {
			logging.Errorf("Failed to send command to agent %s: %v", agentTag, err)
		}
	}()

	return nil
}
