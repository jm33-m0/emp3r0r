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

	// CmdTime store command time
	CmdTime      = make(map[string]string)
	CmdTimeMutex = &sync.Mutex{}
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
	AgentControlMap      = make(map[*def.Emp3r0rAgent]*AgentControl)
	AgentControlMapMutex = sync.RWMutex{}

	// AgentList list of connected agents
	AgentList = make([]*def.Emp3r0rAgent, 0)
)
