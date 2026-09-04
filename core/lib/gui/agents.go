package gui

import "github.com/jm33-m0/emp3r0r/core/internal/live"

// agentListMessage is the frame payload broadcast on every agent refresh. The
// agent snapshots themselves are the shared live.Agent DTOs (declared once in
// internal/live); the operator console builds them from def.Emp3r0rAgent and
// hands them over through ConsoleHost.Agents / PublishAgents.
type agentListMessage struct {
	Type   string      `json:"type"`
	Agents []live.Agent `json:"agents"`
}

// publishAgents pushes a fresh agent snapshot to every connected frontend.
func (g *Backend) publishAgents(agents []live.Agent) {
	g.publish(agentListMessage{Type: "agents", Agents: agents}, false)
}
