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
	c2_ip := common.RuntimeConfig.CCAddress
	transport_type := "[??]"
	rtt := "⚡??ms"
	idle := "Idle: ??s"
	idle_color := "green"

	if live.ActiveAgent != nil {
		c2_ip = live.ActiveAgent.C2Host
		transport_type = fmt.Sprintf("[%s]", live.ActiveAgent.Transport)
		rtt = fmt.Sprintf("⚡%dms", live.ActiveAgent.LastSeenRTT.Milliseconds())

		idle_time := time.Since(live.ActiveAgent.LastSeen).Seconds()
		if live.ActiveAgent.LastSeen.IsZero() {
			idle = "Idle: N/A"
			idle_color = "red"
		} else {
			idle = fmt.Sprintf("Idle: %.0fs", idle_time)
			if idle_time > 120 {
				idle_color = "red"
			} else if idle_time > 45 {
				idle_color = "yellow"
			}
		}
	}

	status_msg := fmt.Sprintf("%s %s | #[fg=%s]%s #[fg=white]| 🛡️ %d Agents | 📡 %s",
		transport_type, rtt, idle_color, idle, len(agents), c2_ip)
	setStatusErr := cli.TmuxSetStatusRight("%s", status_msg)
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
