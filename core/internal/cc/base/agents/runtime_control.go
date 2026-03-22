package agents

import (
	"net"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// RuntimeControlByUUID returns the runtime projection entry for a UUID, if present.
// This helper is for operational/session state only, never for security trust decisions.
func RuntimeControlByUUID(uuid string) (agent *def.Emp3r0rAgent, ctrl *live.AgentControl, key any, found bool) {
	live.AgentControlMap.Range(func(k, v any) bool {
		a, okA := k.(*def.Emp3r0rAgent)
		c, okC := v.(*live.AgentControl)
		if !okA || !okC {
			return true
		}
		if a.UUID == uuid {
			agent, ctrl, key, found = a, c, k, true
			return false
		}
		return true
	})
	return
}

// RuntimeControlByConn returns the runtime projection entry associated with conn, if present.
func RuntimeControlByConn(conn net.Conn) (agent *def.Emp3r0rAgent, ctrl *live.AgentControl, key any, found bool) {
	live.AgentControlMap.Range(func(k, v any) bool {
		a, okA := k.(*def.Emp3r0rAgent)
		c, okC := v.(*live.AgentControl)
		if !okA || !okC {
			return true
		}
		if c.Conn == conn {
			agent, ctrl, key, found = a, c, k, true
			return false
		}
		return true
	})
	return
}
