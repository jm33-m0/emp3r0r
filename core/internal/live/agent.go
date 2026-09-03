package live

import (
	"context"
	"net"
	"sync"
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

// AgentControl controller interface of a target
type AgentControl struct {
	Index  int      // index of a connected agent
	Label  string   // custom label for an agent
	Conn   net.Conn // active C2 stream for this agent (transport-agnostic)
	Ctx    context.Context
	Cancel context.CancelFunc
}

var (
	// AgentControlMap runtime projection of live agent control state.
	//
	// Keys (*def.Emp3r0rAgent) and values (*AgentControl) are treated as
	// immutable after publication: no code may mutate a stored object in place.
	// Updates are published by copying the current snapshot, changing the copy,
	// and re-Storing it (e.g. handleMessageTunnelStream, agents label setters).
	// sync.Map then guarantees every Load/Range observes a consistent,
	// never-mutated value, which keeps concurrent readers (agent lists, SOCKS5
	// pivot startup, message-tunnel teardown) race-free.
	AgentControlMap sync.Map

	// AgentList mirrors the agents this process knows about. On the CC server
	// it is a legacy duplicate of AgentControlMap (agents are admitted there);
	// on the operator console it holds the snapshot list fetched from the CC
	// API by the background agentListRefresher goroutine. It is a sync.Map
	// keyed by agent UUID -> *def.Emp3r0rAgent so the refresher can publish new
	// snapshots while REPL handlers and autocompletion read the list: a plain
	// shared slice would race those goroutines.
	AgentList sync.Map
)
