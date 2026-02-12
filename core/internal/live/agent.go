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
	// PendingKeyRotations stores new public keys for agents that requested rotation
	// key: UUID, value: PublicKey
	PendingKeyRotations sync.Map
)
