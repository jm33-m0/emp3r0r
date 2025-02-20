package agents

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// RenderAgentTable builds and returns a table string for the given agents.
func RenderAgentTable(agents []*emp3r0r_def.Emp3r0rAgent) string {
	// build table data
	tdata := [][]string{}
	var tail []string

	for _, target := range agents {
		ctrl := runtime_def.AgentControlMap[target]
		if ctrl == nil {
			continue
		}
		if ctrl.Label == "" {
			ctrl.Label = "nolabel"
		}
		index := fmt.Sprintf("%d", ctrl.Index)
		label := ctrl.Label
		agentProc := *target.Process
		procInfo := fmt.Sprintf("%s (%d)\n<- %s (%d)",
			agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID)
		ips := strings.Join(target.IPs, ",\n")
		infoMap := map[string]string{
			"OS":      util.SplitLongLine(target.OS, 20),
			"Process": util.SplitLongLine(procInfo, 20),
			"User":    util.SplitLongLine(target.User, 20),
			"From":    fmt.Sprintf("%s\nvia %s", target.From, target.Transport),
			"IPs":     ips,
		}
		row := []string{
			index, label, util.SplitLongLine(target.Tag, 15),
			infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"],
		}
		if runtime_def.ActiveAgent != nil && runtime_def.ActiveAgent.Tag == target.Tag {
			index = color.New(color.FgHiGreen, color.Bold).Sprintf("%d", ctrl.Index)
			row = []string{
				index, label, util.SplitLongLine(target.Tag, 15),
				infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"],
			}
			tail = row
			continue
		}
		tdata = append(tdata, row)
	}
	if tail != nil {
		tdata = append(tdata, tail)
	}

	header := []string{"Index", "Label", "Tag", "OS", "Process", "User", "IPs", "From"}
	return cli.BuildTable(header, tdata)
}

// ListConnectedAgents renders and prints the table of connected agents.
func ListConnectedAgents() {
	agents := GetConnectedAgents()
	tableOutput := RenderAgentTable(agents)
	if cli.AgentListPane == nil {
		logging.Errorf("AgentListPane doesn't exist")
		return
	}
	cli.AgentListPane.Printf(true, "\n\033[0m%s\n\n", tableOutput)
}

// Update agent list, then switch to its tmux window
func CmdLsTargets(cmd *cobra.Command, args []string) {
	ListConnectedAgents()
	cli.TmuxSwitchWindow(cli.AgentListPane.WindowID)
}
