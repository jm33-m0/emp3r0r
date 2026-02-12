package agents

import (
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// DisconnectAllAgents closes all agent connections
// This should be called when the last operator disconnects
func DisconnectAllAgents() {
	count := 0
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if count == 0 {
		return
	}

	logging.Infof("Disconnecting all %d agent(s) due to operator exit", count)

	live.AgentControlMap.Range(func(key, value interface{}) bool {
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
		return true
	})

	// Clear the map
	live.AgentControlMap = sync.Map{}
	logging.Infof("All agents disconnected")
}
