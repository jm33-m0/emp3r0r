package operator

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
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
	}

	// Send command
	err := operatorSendCommand2Agent(fmt.Sprintf("%s", cmdStr), uuid.NewString(), agent.Tag)
	if err != nil {
		logging.Errorf("Error executing command: %v", err)
	} else {
		logging.Debugf("Command sent to %s: %s", agent.Tag, cmdStr)
	}
}
