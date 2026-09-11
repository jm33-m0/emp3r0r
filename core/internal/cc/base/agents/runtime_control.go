package agents

import (
	"net"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// RuntimeControlByUUID returns the runtime projection entry for a UUID, if present.
// This helper is for operational/session state only, never for security trust decisions.
func RuntimeControlByUUID(uuid string) (agent *def.Emp3r0rAgent, ctrl *live.AgentControl, found bool) {
	rec, ok := live.LookupAgent(uuid)
	if !ok {
		return nil, nil, false
	}
	return SnapshotAgent(rec.Agent), rec.Control, true
}

// RuntimeControlByConn returns the runtime projection entry associated with conn, if present.
func RuntimeControlByConn(conn net.Conn) (agent *def.Emp3r0rAgent, ctrl *live.AgentControl, found bool) {
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		if rec.Control != nil && rec.Control.Conn == conn {
			agent, ctrl, found = SnapshotAgent(rec.Agent), rec.Control, true
			return false
		}
		return true
	})
	return agent, ctrl, found
}
