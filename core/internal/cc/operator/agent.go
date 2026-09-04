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
	"github.com/jm33-m0/emp3r0r/core/lib/gui"
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

// setActiveTarget selects an agent (by tag or numeric index) as the active
// target, updates the operator-side pointer and refreshes the agent list. It
// is the shared backend used by both the `target` console command and the GUI
// agent table click. UI-specific side effects (tmux window titles, pane
// switches) are applied by the callers. It returns false when selection
// failed.
func setActiveTarget(identifier string) bool {
	agent, err := client.SetActiveAgent(identifier)
	if err != nil {
		logging.Errorf("Failed to set active agent: %v", err)
		return false
	}
	live.ActiveAgent = agent
	logging.Successf("Now targeting %s", live.ActiveAgent.Tag)

	// Reset operator-idle tracking for the newly selected agent so the status
	// bar shows "Operator idle: 0s" instead of "--".
	markAgentCommandSent(live.ActiveAgent.Tag)

	// Refresh the list immediately so the newly selected agent's Last seen/RTT
	// reflect the latest server state instead of waiting for the next 10s tick.
	safeRefreshAgentList()
	return true
}

// cmdSetActiveAgent sets the active agent for the operator
func CmdSetActiveAgent(cmd *cobra.Command, args []string) {
	if !setActiveTarget(args[0]) {
		return
	}
	if GuiMode {
		return
	}
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
	if GuiMode {
		count := 0
		live.AgentList.Range(func(_, _ any) bool {
			count++
			return true
		})
		logging.Infof("%d agent(s) connected — see the left panel", count)
		return
	}
	cli.TmuxSwitchWindow(cli.AgentListPane.WindowID)
}

// RenderAgentTable builds and returns a table string for the given agents.
func RenderAgentTable(agents []*def.Emp3r0rAgent) {
	// In GUI mode the frontend renders its own table / mesh view from a
	// structured snapshot (gui_agents.go), so skip all tmux logic here.
	if GuiMode {
		gui.PublishAgents(guiAgentViews(agents))
		return
	}
	// build table data
	tdata := [][]string{}
	var tail []string

	for _, target := range agents {
		if target == nil {
			continue
		}
		procInfo := agentProcessString(target)
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
			agentLastSeen(target),
		}
		if live.ActiveAgent != nil && live.ActiveAgent.Tag == target.Tag {
			tail = row
			continue
		}
		tdata = append(tdata, row)
	}
	if tail != nil {
		tdata = append(tdata, tail)
	}

	// Set tmux status with agent count, RTT, agent last-seen and operator idle.
	rtt := "⚡--"
	lastSeen := "Last seen: --"
	lastSeenColor := "red"
	operatorIdle := "Operator idle: --"
	operatorIdleColor := "red"

	if live.ActiveAgent != nil {
		// Use the freshly-fetched agent entry rather than the possibly stale
		// live.ActiveAgent pointer, so LastSeen/RTT always reflect the server's
		// latest state for the selected agent.
		var active *def.Emp3r0rAgent
		for _, a := range agents {
			if a != nil && a.UUID == live.ActiveAgent.UUID {
				active = a
				break
			}
		}

		if active == nil {
			// The selected agent is no longer in the connected-agent list.
			// Show this explicitly instead of a stale, ever-growing idle time.
			rtt = "⚡--"
			lastSeen = "Agent offline"
			lastSeenColor = "red"
		} else {
			if active.LastSeenRTT > 0 {
				rtt = fmt.Sprintf("⚡%.1fms", float64(active.LastSeenRTT)/float64(time.Millisecond))
			} else {
				rtt = "⚡0ms"
			}

			lastSeenTime := time.Since(active.LastSeen).Seconds()
			if active.LastSeen.IsZero() {
				lastSeen = "Last seen: --"
				lastSeenColor = "red"
			} else {
				lastSeen = fmt.Sprintf("Last seen: %s", formatIdle(lastSeenTime))
				if lastSeenTime > 240 {
					lastSeenColor = "red"
				} else if lastSeenTime > 120 {
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

	// Status Right: RTT | Last seen | Operator idle.
	// When no target is selected, avoid showing a misleading red "timeout"
	// status; the per-agent Last seen column in the list carries that info.
	var status_right string
	if live.ActiveAgent == nil {
		status_right = fmt.Sprintf("#[fg=colour15,bg=colour235,bold] %s | #[fg=yellow]No active target ",
			rtt)
	} else {
		status_right = fmt.Sprintf("#[fg=colour15,bg=colour235,bold] %s | #[fg=%s]%s | #[fg=%s]%s ",
			rtt, lastSeenColor, lastSeen, operatorIdleColor, operatorIdle)
	}
	_ = cli.TmuxSetStatusRight(status_right)

	header := []string{"ID", "Tag", "OS", "Process", "User", "IPs", "From", "C2", "Mesh", "Last seen"}
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

// agentProcessString renders an agent's process for display (CLI table and
// the GUI agent snapshot share this formatter).
func agentProcessString(a *def.Emp3r0rAgent) string {
	if a == nil || a.Process == nil {
		return "unknown"
	}
	p := *a.Process
	return fmt.Sprintf("%s (%d) <- %s (%d)", p.Cmdline, p.PID, p.Parent, p.PPID)
}

// guiAgentViews maps the canonical agent records to the GUI's wire DTOs. This
// is the single def -> gui.Agent conversion in the codebase; lib/gui never
// imports internal/def. It reuses the same display helpers as the CLI table.
func guiAgentViews(agents []*def.Emp3r0rAgent) []gui.Agent {
	views := make([]gui.Agent, 0, len(agents))
	for _, a := range agents {
		if a == nil {
			continue
		}
		active := live.ActiveAgent != nil && live.ActiveAgent.Tag == a.Tag
		v := gui.Agent{
			ID:             a.ShortID,
			Tag:            a.Tag,
			Name:           a.Name,
			UUID:           a.UUID,
			Version:        a.Version,
			OS:             a.OS,
			Goos:           a.GOOS,
			Arch:           a.GOArch,
			User:           a.User,
			Process:        agentProcessString(a),
			IPs:            a.IPs,
			From:           a.From,
			Transport:      a.Transport,
			MeshRoute:      a.MeshRoute,
			P2PRelayPort:   a.P2PRelayPort,
			MeshGossipPort: a.MeshGossipPort,
			CWD:            a.CWD,
			HasRoot:        a.HasRoot,
			LastSeen:       agentLastSeen(a),
			Active:         active,
		}
		if a.LastSeenRTT > 0 {
			v.LastSeenRTT = float64(a.LastSeenRTT) / float64(time.Millisecond)
		}
		views = append(views, v)
	}
	return views
}

// agentLastSeen formats an agent's last-seen time for display in the agent list.
func agentLastSeen(a *def.Emp3r0rAgent) string {
	if a == nil || a.LastSeen.IsZero() {
		return "--"
	}
	return formatIdle(time.Since(a.LastSeen).Seconds())
}

// safeRefreshAgentList runs refreshAgentList and never lets a panic stop the
// refresher loop.
func safeRefreshAgentList() {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("refreshAgentList panicked: %v", r)
		}
	}()
	if err := refreshAgentList(); err != nil {
		logging.Errorf("Failed to refresh agent list: %v", err)
	}
}

// AgentListRefresher refreshes agent list every 10 seconds
func agentListRefresher() {
	safeRefreshAgentList() // refresh immediately
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-AgentRefreshCh:
			safeRefreshAgentList()
		case <-ticker.C:
			safeRefreshAgentList()
		}
	}
}

// refreshAgentList refreshes agent list from server
func refreshAgentList() error {
	agents, err := client.GetAgentList()
	if err != nil {
		return err
	}
	if logging.Level >= 4 {
		for _, a := range agents {
			logging.Debugf("refreshAgentList: %s LastSeen=%v (%.0fs ago)", a.Tag, a.LastSeen, time.Since(a.LastSeen).Seconds())
		}
	}
	// Publish the refreshed list as an immutable snapshot set (agent UUID ->
	// agent). live.AgentList is a sync.Map because this refresher runs on its
	// own goroutine while REPL handlers and autocompletion read the list.
	live.AgentList.Clear()
	for _, a := range agents {
		if a != nil && a.UUID != "" {
			live.AgentList.Store(a.UUID, a)
		}
	}
	// Update active agent pointer to avoid staleness
	if live.ActiveAgent != nil {
		for _, a := range agents {
			if a.UUID == live.ActiveAgent.UUID {
				live.ActiveAgent = a
				// Update tmux window title
				if !GuiMode {
					_ = cli.TmuxSetWindowTitle(live.ActiveAgent.ShortID, cli.CommandPane.WindowID)
				}
				break
			}
		}
	}

	RenderAgentTable(agents)
	return nil
}
