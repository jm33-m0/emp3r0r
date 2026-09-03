package agents

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// DisconnectAgentByUUID closes one agent's live runtime session, if present.
// It also clears DB session state and runtime projections for that UUID.
func DisconnectAgentByUUID(uuid string) bool {
	if uuid == "" {
		return false
	}

	agent, ctrl, key, found := RuntimeControlByUUID(uuid)
	if !found {
		if err := EndSession(uuid); err != nil {
			logging.Debugf("Failed to end session for %s: %v", uuid, err)
		}
		return false
	}

	if ctrl != nil {
		if ctrl.Cancel != nil {
			ctrl.Cancel()
		}
		if ctrl.Conn != nil {
			if err := ctrl.Conn.Close(); err != nil {
				logging.Debugf("Error closing connection for agent %s (%s): %v", agent.Tag, uuid, err)
			}
		}
	}

	live.AgentControlMap.Delete(key)
	live.AgentList.Delete(uuid)

	if err := EndSession(uuid); err != nil {
		logging.Debugf("Failed to end session for %s: %v", uuid, err)
	}

	logging.Warningf("Disconnected live session for agent %s (%s)", agent.Tag, uuid)
	return true
}

// DisconnectAllAgents closes all agent connections
// This should be called when the last operator disconnects
func DisconnectAllAgents() {
	count := 0
	live.AgentControlMap.Range(func(key, value any) bool {
		count++
		return true
	})
	if count == 0 {
		return
	}

	logging.Infof("Disconnecting all %d agent(s) due to operator exit", count)

	live.AgentControlMap.Range(func(key, value any) bool {
		agent := key.(*def.Emp3r0rAgent)
		ctrl := value.(*live.AgentControl)
		if ctrl == nil {
			return true
		}

		// Close the connection
		if ctrl.Conn != nil {
			if err := ctrl.Conn.Close(); err != nil {
				logging.Debugf("Error closing connection for agent %s: %v", agent.Tag, err)
			}
		}

		// Cancel the context
		if ctrl.Cancel != nil {
			ctrl.Cancel()
		}

		// End DB session tracking
		if err := EndSession(agent.UUID); err != nil {
			logging.Debugf("Failed to end session for %s: %v", agent.UUID, err)
		}

		return true
	})

	// Clear both registries. sync.Map.Clear (Go 1.23+) is safe to call while
	// other goroutines are still using the same map variable; reassigning
	// `= sync.Map{}` would race any concurrent Load/Range on the old value.
	live.AgentControlMap.Clear()
	live.AgentList.Clear()
	logging.Infof("All agents disconnected")
}
