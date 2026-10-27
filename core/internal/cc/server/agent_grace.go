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

// agentDisconnectState identifies the latest offline event for a UUID and lets
// a reconnect cancel its timer. done closes once the timer callback has fully
// finished (including EndSession), so a caller replacing the agent database
// never races a still-running grace callback.
type agentDisconnectState struct {
	gen   int64
	timer *time.Timer
	done  chan struct{}
	once  sync.Once
}

func (s *agentDisconnectState) finish() {
	if s == nil {
		return
	}
	s.once.Do(func() { close(s.done) })
}

// agentDisconnectGen distinguishes the latest offline event for a UUID from
// older delayed-forget timers.
var agentDisconnectGen sync.Map // uuid -> *agentDisconnectState

// cancelAgentOffline stops the pending grace callback and waits until it has
// finished. It must be called before tearing down or replacing process-wide
// state that the callback touches (notably the agent database).
func cancelAgentOffline(uuid string) {
	v, ok := agentDisconnectGen.LoadAndDelete(uuid)
	if !ok {
		return
	}
	st, ok := v.(*agentDisconnectState)
	if !ok || st == nil {
		return
	}
	if st.timer.Stop() {
		// The callback never ran; close done ourselves.
		st.finish()
	}
	<-st.done
}

// markAgentReconnected cancels any pending offline-expiry for the agent.
func markAgentReconnected(uuid string) {
	if uuid != "" {
		cancelAgentOffline(uuid)
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
	cancelAgentOffline(agent.UUID)
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

	// A repeated disconnect replaces the previous deadline. Wait for the old
	// callback to finish so two timers can never race over the same agent.
	cancelAgentOffline(agent.UUID)
	st := &agentDisconnectState{
		gen:  time.Now().UnixNano(),
		done: make(chan struct{}),
	}
	agentDisconnectGen.Store(agent.UUID, st)
	announced := false
	if rec, ok := live.LookupAgent(agent.UUID); ok {
		announced = rec.Announced
	}
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: nil, Announced: announced})

	st.timer = time.AfterFunc(grace, func() {
		defer st.finish()
		cur, ok := agentDisconnectGen.Load(agent.UUID)
		if !ok || cur != st {
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
		if removed {
			operatorBroadcastPrintf(logging.ERROR,
				"Agent dies... %s is disconnected", util.AgentRef(agent.UUID))
		}
		_ = agents.EndSession(agent.UUID)
		// Keep the state visible until EndSession returns: a reconnect or test
		// cleanup that finds it here must be able to wait for the callback.
		agentDisconnectGen.Delete(agent.UUID)
	})
}
