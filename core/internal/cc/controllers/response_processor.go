package controllers

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// ProcessedResponse contains processed agent response data
type ProcessedResponse struct {
	Agent       *def.Emp3r0rAgent
	Command     string
	Output      string
	JobID       string
	TimeSpent   time.Duration
	IsBuiltin   bool
	ShouldShow  bool
	MessageType string // "success", "error", "warn", "info", "output"
}

// ProcessAgentResponse processes agent data and returns structured response
// This is pure business logic - no UI rendering
func ProcessAgentResponse(data *def.MsgTunData) (*ProcessedResponse, error) {
	resp := &ProcessedResponse{
		JobID: data.JobID,
	}

	// Check if this is a broadcast message
	switch data.Tag {
	case "SUCCESS":
		resp.MessageType = "success"
		resp.Output = string(data.Response)
		resp.ShouldShow = true
		return resp, nil
	case "ERROR":
		resp.MessageType = "error"
		resp.Output = string(data.Response)
		resp.ShouldShow = true
		return resp, nil
	case "WARN":
		resp.MessageType = "warn"
		resp.Output = string(data.Response)
		resp.ShouldShow = true
		return resp, nil
	case "INFO":
		resp.MessageType = "info"
		resp.Output = string(data.Response)
		resp.ShouldShow = true
		return resp, nil
	}

	// Find target agent
	var target *def.Emp3r0rAgent
	if data.AgentUUID != "" {
		target = agents.GetAgentByUUID(data.AgentUUID)
	}
	if target == nil {
		target = agents.GetAgentByTag(data.Tag)
	}

	if target == nil {
		return nil, fmt.Errorf("target %s (%s) cannot be found, message: %v",
			data.Tag, data.AgentUUID, data.CmdSlice)
	}

	resp.Agent = target
	resp.MessageType = "output"

	// Update agent state
	target.LastSeen = time.Now()

	// Extract command info
	if len(data.CmdSlice) == 0 {
		return nil, fmt.Errorf("empty command slice")
	}
	resp.Command = data.CmdSlice[0]
	resp.IsBuiltin = strings.HasPrefix(resp.Command, "!")
	resp.Output = string(data.Response)

	// Cache command result
	live.CmdResults.Store(data.JobID, resp.Output)
	// Signal any waiting goroutine that a result is ready.
	if ch, ok := live.CmdResultsReady.LoadAndDelete(data.JobID); ok {
		close(ch.(chan struct{}))
	}

	// Calculate time spent
	if val, ok := live.CmdTime.Load(data.JobID); ok {
		cmdtime := val.(string)
		startTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", cmdtime)
		if err == nil {
			resp.TimeSpent = time.Since(startTime)
			target.LastSeenRTT = resp.TimeSpent
			target.LastSeen = time.Now()
		}
	}

	// Determine if output should be shown
	noNeedToShow := strings.HasPrefix(resp.Command, def.C2CmdPortFwd) ||
		strings.HasPrefix(resp.Command, def.C2CmdSSHD) ||
		strings.HasPrefix(resp.Command, def.C2CmdListDir)

	resp.ShouldShow = !noNeedToShow

	return resp, nil
}
