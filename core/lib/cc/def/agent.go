package def

import (
	"context"
	"sync"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/posener/h2conn"
)

var (
	// CmdResults receive response from agent and cache them
	CmdResults      = make(map[string]string)
	CmdResultsMutex = &sync.Mutex{}

	// CmdTime store command time
	CmdTime      = make(map[string]string)
	CmdTimeMutex = &sync.Mutex{}
)

// AgentControl controller interface of a target
type AgentControl struct {
	Index  int          // index of a connected agent
	Label  string       // custom label for an agent
	Conn   *h2conn.Conn // h2 connection of an agent
	Ctx    context.Context
	Cancel context.CancelFunc
}

var (
	// AgentControlMap target list, with control (tun) interface
	AgentControlMap      = make(map[*emp3r0r_def.Emp3r0rAgent]*AgentControl)
	AgentControlMapMutex = sync.RWMutex{}
)
