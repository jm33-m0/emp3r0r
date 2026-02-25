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

// AgentControl controller interface of a target
type AgentControl struct {
	Index  int      // index of a connected agent
	Label  string   // custom label for an agent
	Conn   net.Conn // h2 connection of an agent
	Ctx    context.Context
	Cancel context.CancelFunc
}

var (
	// AgentControlMap target list, with control (tun) interface
	AgentControlMap sync.Map

	// AgentList list of connected agents
	AgentList = make([]*def.Emp3r0rAgent, 0)
)
