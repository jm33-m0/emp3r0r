package operator

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// cmdSetActiveAgent sets the active agent for the operator
func CmdSetActiveAgent(cmd *cobra.Command, args []string) {
	agent, err := client.SetActiveAgent(args[0])
	if err != nil {
		logging.Errorf("Failed to set active agent: %v", err)
		return
	}
	live.ActiveAgent = agent
	logging.Successf("Now targeting %s", live.ActiveAgent.Tag)

	// Update tmux window title to show active agent
	setTitleErr := cli.TmuxSetWindowTitle(live.ActiveAgent.ShortID, cli.CommandPane.WindowID)
	if setTitleErr != nil {
		logging.Warningf("Failed to set tmux window title: %v", setTitleErr)
	}
}

// cmdListAgents triggers a refresh of the agent list and switches to the agent list pane
func CmdListAgents(_ *cobra.Command, _ []string) {
	err := refreshAgentList()
	if err != nil {
		logging.Errorf("Failed to list agents: %v", err)
		return
	}
	cli.TmuxSwitchWindow(cli.AgentListPane.WindowID)
}

// RenderAgentTable builds and returns a table string for the given agents.
func RenderAgentTable(agents []*def.Emp3r0rAgent) {
	// build table data
	tdata := [][]string{}
	var tail []string

	for _, target := range agents {
		procInfo := "unknown"
		if target.Process != nil {
			agentProc := *target.Process
			procInfo = fmt.Sprintf("%s (%d) <- %s (%d)",
				agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID)
		}
		ips := strings.Join(target.IPs, ", ")
		infoMap := map[string]string{
			"OS":      util.SplitLongLine(target.OS, 20),
			"Process": util.SplitLongLine(procInfo, 20),
			"User":    util.SplitLongLine(target.User, 20),
			"From":    fmt.Sprintf("%s via %s", target.From, target.Transport),
			"IPs":     ips,
		}
		row := []string{
			target.ShortID,
			util.SplitLongLine(target.Tag, 15),
			infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"],
		}
		if live.ActiveAgent != nil && live.ActiveAgent.Tag == target.Tag {
			row = []string{
				target.ShortID,
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

	// Set tmux status with agent count and RTT/Idle info
	rtt := "⚡??ms"
	idle := "Idle: ??s"
	idle_color := "green"

	if live.ActiveAgent != nil {
		if live.ActiveAgent.LastSeenRTT > 0 {
			rtt = fmt.Sprintf("⚡%.1fms", float64(live.ActiveAgent.LastSeenRTT)/float64(time.Millisecond))
		} else {
			rtt = "⚡0ms"
		}

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

	// Status Left: [emp3r0r] 🛡️ AgentCount
	status_left := fmt.Sprintf("#[fg=colour15,bg=colour235,bold] [emp3r0r] #[fg=%s,bg=colour235,nobold]🛡️ %d Agents ",
		agentCountColor, len(agents))
	_ = cli.TmuxSetStatusLeft(status_left)

	// Status Right: RTT | Idle: Time
	status_right := fmt.Sprintf("#[fg=colour15,bg=colour235,bold] %s | #[fg=%s]%s ",
		rtt, idle_color, idle)
	_ = cli.TmuxSetStatusRight(status_right)

	header := []string{"ID", "Tag", "OS", "Process", "User", "IPs", "From"}
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
	agents, err := client.GetAgentList()
	if err != nil {
		return err
	}
	live.AgentList = agents
	// Update active agent pointer to avoid staleness
	if live.ActiveAgent != nil {
		for _, a := range agents {
			if a.UUID == live.ActiveAgent.UUID {
				live.ActiveAgent = a
				// Update tmux window title
				_ = cli.TmuxSetWindowTitle(live.ActiveAgent.ShortID, cli.CommandPane.WindowID)
				break
			}
		}
	}

	RenderAgentTable(live.AgentList)
	return nil
}
