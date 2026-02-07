package operator

import (
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdSysinfo sends sysinfo command to the agent
func CmdSysinfo(cmd *cobra.Command, args []string) {
	// Parse flags
	full, _ := cmd.Flags().GetBool("full")
	cpu, _ := cmd.Flags().GetBool("cpu")
	mem, _ := cmd.Flags().GetBool("mem")
	osInfo, _ := cmd.Flags().GetBool("os")
	net, _ := cmd.Flags().GetBool("net")
	user, _ := cmd.Flags().GetBool("user")
	container, _ := cmd.Flags().GetBool("container")
	uptime, _ := cmd.Flags().GetBool("uptime")

	agent := agents.MustGetActiveAgent()
	if agent == nil {
		logging.Errorf("No active agent, use `target` command to select one")
		return
	}

	cmdStr := "sysinfo"
	if full {
		cmdStr += " --full"
	} else {
		if cpu {
			cmdStr += " --cpu"
		}
		if mem {
			cmdStr += " --mem"
		}
		if osInfo {
			cmdStr += " --os"
		}
		if net {
			cmdStr += " --net"
		}
		if user {
			cmdStr += " --user"
		}
		if container {
			cmdStr += " --container"
		}
		if uptime {
			cmdStr += " --uptime"
		}
	}

	// Send command
	ctx := &c2context.C2Context{
		Target:    agent,
		OpSession: OPERATOR_SESSION,
		Flags:     make(map[string]string),
	}
	ctx.Flags["cmd_to_exec"] = cmdStr
	modules.ModuleCmd(ctx)
	logging.Debugf("Command sent to %s: %s", agent.Tag, cmdStr)
}
