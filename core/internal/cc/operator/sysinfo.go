package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdSysinfo sends sysinfo command to the agent
// This is now a thin wrapper that parses flags and calls controller
func CmdSysinfo(cmd *cobra.Command, args []string) {
	agent := agents.MustGetActiveAgent()
	if agent == nil {
		logging.Errorf("No active agent, use `target` command to select one")
		return
	}

	// Parse flags into options struct
	opts := controllers.SysinfoOptions{
		Full:      mustGetBool(cmd, "full"),
		CPU:       mustGetBool(cmd, "cpu"),
		Mem:       mustGetBool(cmd, "mem"),
		OS:        mustGetBool(cmd, "os"),
		Net:       mustGetBool(cmd, "net"),
		User:      mustGetBool(cmd, "user"),
		Container: mustGetBool(cmd, "container"),
		Uptime:    mustGetBool(cmd, "uptime"),
	}

	// Call controller (business logic)
	err := controllers.ExecuteSysinfoCommand(agent, opts, OPERATOR_SESSION)
	if err != nil {
		logging.Errorf("Failed to execute sysinfo: %v", err)
		return
	}

	logging.Debugf("Sysinfo command sent to %s", agent.Tag)
}

// mustGetBool is a helper to get bool flag without error handling
func mustGetBool(cmd *cobra.Command, name string) bool {
	val, _ := cmd.Flags().GetBool(name)
	return val
}
