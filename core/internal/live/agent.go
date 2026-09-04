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

// Agent is the canonical operator-side snapshot of one connected agent, ready
// for presentation (JSON for the GUI, or reused by any other frontend). It is
// deliberately a plain DTO: the operator console builds it from the canonical
// internal/def.Emp3r0rAgent (see operator.guiAgentViews) and injects it into
// presentations via their host interface — the type lives here, next to
// AgentList, so it is declared exactly once and never duplicated.
//
// Field names/tags are part of the GUI wire contract; keep them stable.
type Agent struct {
	ID             string   `json:"id"` // ShortID, same identifier shown by the CLI table
	Tag            string   `json:"tag"`
	Name           string   `json:"name"`
	UUID           string   `json:"uuid"`
	Version        string   `json:"version"`
	OS             string   `json:"os"`
	Goos           string   `json:"goos"` // runtime.GOOS of the agent binary ("linux", "windows", ...)
	Arch           string   `json:"arch"`
	User           string   `json:"user"`
	Process        string   `json:"process"`
	IPs            []string `json:"ips"`
	From           string   `json:"from"`
	Transport      string   `json:"transport"`
	MeshRoute      string   `json:"meshRoute"`
	P2PRelayPort   string   `json:"p2pRelayPort"`
	MeshGossipPort string   `json:"meshGossipPort"`
	CWD            string   `json:"cwd"`
	HasRoot        bool     `json:"hasRoot"`
	LastSeen       string   `json:"lastSeen"`
	LastSeenRTT    float64  `json:"lastSeenRttMs"`
	Active         bool     `json:"active"`
}

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
