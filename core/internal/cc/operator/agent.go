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

	// Agent Count Color
	agentCountColor := "red"
	if len(agents) > 0 {
		agentCountColor = "green"
	}

	// Status Left: [emp3r0r] 🛡️ AgentCount | 📡 C2Address
	status_left := fmt.Sprintf("#[fg=colour15,bg=colour235,bold] [emp3r0r] #[fg=%s,bg=colour235,nobold]🛡️ %d Agents #[fg=white]| 📡 %s ",
		agentCountColor, len(agents), util.ShortenString(c2_ip, 20))
	_ = cli.TmuxSetStatusLeft("%s", status_left)

	// Status Right: Transport RTT | Idle: Time
	status_right := fmt.Sprintf("#[fg=colour15,bg=colour235,bold] %s %s | #[fg=%s]%s ",
		transport_type, rtt, idle_color, idle)
	_ = cli.TmuxSetStatusRight("%s", status_right)

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
	refreshAgentList() // refresh immediately
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-AgentRefreshCh:
			refreshAgentList()
		case <-ticker.C:
			refreshAgentList()
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
