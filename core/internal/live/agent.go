package live

import (
	"context"
	"net"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

var (
	// CmdResults receive response from agent and cache them
	CmdResults = sync.Map{}

	// CmdResultsReady holds per-job-id notification channels.
	// A caller populates this before sending a command:
	//   ch := make(chan struct{}, 1)
	//   live.CmdResultsReady.Store(jobID, ch)
	// When a result arrives, the channel is closed so any waiter wakes up.
	CmdResultsReady = sync.Map{}

	// CmdTime store command time
	CmdTime sync.Map
)

// AgentControl holds the live message-tunnel state for one agent. It is owned
// by the C2 server process, which terminates the agent's tunnel; the operator
// process never has a Control for its agents (it reaches them through the C2
// operator API instead).
type AgentControl struct {
	Index  int      // index of a connected agent
	Conn   net.Conn // active C2 stream for this agent (transport-agnostic)
	Ctx    context.Context
	Cancel context.CancelFunc
}

// AgentRecord is an immutable snapshot of one agent known to this process.
//
// Agent is always set. Control is non-nil only in the C2 server process, which
// owns the agent's live tunnel; in the operator process it is nil. Label is
// presentation metadata that either role may maintain so a labeled agent keeps
// its name regardless of which side set it.
//
// A published AgentRecord is never mutated in place: readers snapshot fields
// and writers copy the record, change the copy, and publish it.
type AgentRecord struct {
	Agent   *def.Emp3r0rAgent
	Control *AgentControl
	Label   string
}

// AgentRegistry is the single process-local registry of agents, keyed by agent
// UUID. It replaces the former pair of maps -- AgentControlMap (server, keyed
// by *def.Emp3r0rAgent) and AgentList (operator, keyed by UUID) -- whose
// different shapes forced every shared lookup to probe both and let the two
// views drift apart. Keying by the stable UUID also means a re-check-in updates
// the existing entry in place instead of leaving a stale pointer-keyed
// duplicate behind.
var AgentRegistry sync.Map

// LookupAgent returns the registry record for uuid. The returned record must be
// treated as immutable.
func LookupAgent(uuid string) (*AgentRecord, bool) {
	if uuid == "" {
		return nil, false
	}
	v, ok := AgentRegistry.Load(uuid)
	if !ok {
		return nil, false
	}
	rec, ok := v.(*AgentRecord)
	if !ok || rec == nil || rec.Agent == nil {
		return nil, false
	}
	return rec, true
}

// PublishAgent stores rec in the registry. Callers pass a fresh record
// (copy-modify-publish); the registry never mutates a published record.
func PublishAgent(rec *AgentRecord) {
	if rec == nil || rec.Agent == nil || rec.Agent.UUID == "" {
		return
	}
	AgentRegistry.Store(rec.Agent.UUID, rec)
}

// ForgetAgent removes uuid from the registry.
func ForgetAgent(uuid string) {
	AgentRegistry.Delete(uuid)
}

// ClearAgents empties the registry. Clear (Go 1.23+) is safe while other
// goroutines still use the same map variable; reassigning a fresh sync.Map would
// race concurrent Load/Range on the old value.
func ClearAgents() {
	AgentRegistry.Clear()
}

// RangeAgents iterates the published records until fn returns false.
func RangeAgents(fn func(*AgentRecord) bool) {
	AgentRegistry.Range(func(_, v any) bool {
		rec, ok := v.(*AgentRecord)
		if !ok || rec == nil || rec.Agent == nil {
			return true
		}
		return fn(rec)
	})
}
