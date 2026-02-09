package agents

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// DisconnectAllAgents closes all agent connections
// This should be called when the last operator disconnects
func DisconnectAllAgents() {
	live.AgentControlMapMutex.Lock()
	defer live.AgentControlMapMutex.Unlock()

	count := len(live.AgentControlMap)
	if count == 0 {
		return
	}

	logging.Infof("Disconnecting all %d agent(s) due to operator exit", count)

	for agent, ctrl := range live.AgentControlMap {
		if ctrl == nil {
			continue
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
	}

	// Clear the map
	live.AgentControlMap = make(map[*def.Emp3r0rAgent]*live.AgentControl)
	logging.Infof("All agents disconnected")
}
