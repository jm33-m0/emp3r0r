package operator

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// RenderAgentTable builds and returns a table string for the given agents.
func RenderAgentTable(agents []*def.Emp3r0rAgent) {
	// build table data
	tdata := [][]string{}
	var tail []string

	for _, target := range agents {
		agentProc := *target.Process
		procInfo := fmt.Sprintf("%s (%d) <- %s (%d)",
			agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID)
		ips := strings.Join(target.IPs, ", ")
		infoMap := map[string]string{
			"OS":      util.SplitLongLine(target.OS, 20),
			"Process": util.SplitLongLine(procInfo, 20),
			"User":    util.SplitLongLine(target.User, 20),
			"From":    fmt.Sprintf("%s via %s", target.From, target.Transport),
			"IPs":     ips,
		}
		row := []string{
			util.SplitLongLine(target.Tag, 15),
			infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"],
		}
		if live.ActiveAgent != nil && live.ActiveAgent.Tag == target.Tag {
			row = []string{
				util.SplitLongLine(target.Tag, 15),
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

	// Set tmux status with agent count and C2 status
	color := "red"
	if len(agents) > 0 {
		color = "green"
	}
	c2_ip := common.RuntimeConfig.CCAddress
	if live.ActiveAgent != nil {
		c2_ip = live.ActiveAgent.C2Host
	}
	setStatusErr := cli.TmuxSetStatusRight("C2: #[fg=grey]%s #[fg=%s]%d #[fg=white]agents", c2_ip, color, len(agents))
	if setStatusErr != nil {
		logging.Warningf("Failed to set tmux status: %v", setStatusErr)
	}

	header := []string{"Tag", "OS", "Process", "User", "IPs", "From"}
	tabStr := cli.BuildTable(header, tdata)
	if cli.AgentListPane != nil {
		cli.AgentListPane.Printf(true, "%s", tabStr)
	}
}

// AgentListRefresher refreshes agent list every 10 seconds
func agentListRefresher() {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("agentListRefresher panicked: %v", r)
		}
	}()
	retryCount := 0
	maxRetries := 3
	for {
		err := refreshAgentList()
		if err != nil {
			retryCount++
			if retryCount >= maxRetries {
				// Sleep longer on repeated failures to avoid CPU spinning
				time.Sleep(30 * time.Second)
				retryCount = 0
			} else {
				time.Sleep(10 * time.Second)
			}
		} else {
			retryCount = 0
			time.Sleep(10 * time.Second)
		}
	}
}

// refreshAgentList refreshes agent list from server
func refreshAgentList() error {
	err := getAgentListFromServer()
	if err != nil {
		return err
	}

	RenderAgentTable(live.AgentList)
	return nil
}
