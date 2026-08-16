package operator

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// lastCommandSent tracks, for each agent tag, when the operator last
// successfully dispatched a command to that agent. It is keyed by agent tag
// because command dispatch is reported with the tag and the active agent is
// looked up by tag in RenderAgentTable.
var lastCommandSent sync.Map // agentTag -> time.Time

// markAgentCommandSent records that the agent with the given tag has just
// received a command from this operator.
func markAgentCommandSent(agentTag string) {
	if agentTag == "" {
		return
	}
	lastCommandSent.Store(agentTag, time.Now())
}

// operatorIdleFor returns how long ago the operator last sent a command to the
// given agent tag. The second return value reports whether a command has been
// sent yet.
func operatorIdleFor(agentTag string) (time.Duration, bool) {
	val, ok := lastCommandSent.Load(agentTag)
	if !ok {
		return 0, false
	}
	last, ok := val.(time.Time)
	if !ok || last.IsZero() {
		return 0, false
	}
	return time.Since(last), true
}

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
			"From":    target.From,
			"C2":      util.SplitLongLine(target.Transport, 20),
			"Mesh":    util.SplitLongLine(target.MeshRoute, 18),
			"IPs":     ips,
		}
		row := []string{
			target.ShortID,
			util.SplitLongLine(target.Tag, 15),
			infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"], infoMap["C2"], infoMap["Mesh"],
		}
		if live.ActiveAgent != nil && live.ActiveAgent.Tag == target.Tag {
			row = []string{
				target.ShortID,
				util.SplitLongLine(target.Tag, 15),
				infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"], infoMap["C2"], infoMap["Mesh"],
			}
			tail = row
			continue
		}
		tdata = append(tdata, row)
	}
	if tail != nil {
		tdata = append(tdata, tail)
	}

	// Set tmux status with agent count, RTT, agent last-seen and operator idle.
	rtt := "⚡??ms"
	lastSeen := "Last seen: N/A"
	lastSeenColor := "red"
	operatorIdle := "Operator idle: N/A"
	operatorIdleColor := "red"

	if live.ActiveAgent != nil {
		connected := false
		for _, a := range agents {
			if a != nil && a.UUID == live.ActiveAgent.UUID {
				connected = true
				break
			}
		}

		if !connected {
			// The selected agent is no longer in the connected-agent list.
			// Show this explicitly instead of a stale, ever-growing idle time.
			rtt = "⚡N/A"
			lastSeen = "Agent offline"
			lastSeenColor = "red"
		} else if live.ActiveAgent.LastSeenRTT > 0 {
			rtt = fmt.Sprintf("⚡%.1fms", float64(live.ActiveAgent.LastSeenRTT)/float64(time.Millisecond))
		} else {
			rtt = "⚡0ms"
		}

		if connected {
			lastSeenTime := time.Since(live.ActiveAgent.LastSeen).Seconds()
			if live.ActiveAgent.LastSeen.IsZero() {
				lastSeen = "Last seen: N/A"
				lastSeenColor = "red"
			} else {
				lastSeen = fmt.Sprintf("Last seen: %s", formatIdle(lastSeenTime))
				if lastSeenTime > 120 {
					lastSeenColor = "red"
				} else if lastSeenTime > 45 {
					lastSeenColor = "yellow"
				} else {
					lastSeenColor = "green"
				}
			}
		}

		if opIdle, ok := operatorIdleFor(live.ActiveAgent.Tag); ok {
			operatorIdle = fmt.Sprintf("Operator idle: %s", formatIdle(opIdle.Seconds()))
			operatorIdleColor = "green"
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

	// Status Right: RTT | Last seen | Operator idle
	status_right := fmt.Sprintf("#[fg=colour15,bg=colour235,bold] %s | #[fg=%s]%s | #[fg=%s]%s ",
		rtt, lastSeenColor, lastSeen, operatorIdleColor, operatorIdle)
	_ = cli.TmuxSetStatusRight(status_right)

	header := []string{"ID", "Tag", "OS", "Process", "User", "IPs", "From", "C2", "Mesh"}
	tabStr := cli.BuildTable(header, tdata)
	if cli.AgentListPane != nil {
		cli.AgentListPane.Printf(true, "%s", tabStr)
	}
}

// formatIdle renders an idle duration in a compact human-readable form
// (seconds, minutes, hours, or days) instead of a raw second count.
func formatIdle(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	total := int64(seconds)
	days := total / 86400
	hours := (total % 86400) / 3600
	minutes := (total % 3600) / 60
	secs := total % 60

	switch {
	case days > 0:
		if hours > 0 {
			return fmt.Sprintf("%dd%dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	case hours > 0:
		if minutes > 0 {
			return fmt.Sprintf("%dh%dm", hours, minutes)
		}
		return fmt.Sprintf("%dh", hours)
	case minutes > 0:
		if secs > 0 {
			return fmt.Sprintf("%dm%ds", minutes, secs)
		}
		return fmt.Sprintf("%dm", minutes)
	default:
		return fmt.Sprintf("%ds", secs)
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
