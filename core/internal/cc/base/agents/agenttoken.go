package agents

import (
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// agentTokens caches the most recent AgentToken issued to each agent UUID.
//
// The token must NOT be stored on the shared *def.Emp3r0rAgent objects used as
// AgentControlMap keys: the message-tunnel goroutine refreshes tokens while
// other goroutines snapshot those same objects (SnapshotAgent, agent listings,
// SOCKS5 pivot startup), and mutating the shared key in place is a data race.
// Keeping the cache in a side map keyed by UUID gives writers and readers
// race-free access via sync.Map.
var agentTokens sync.Map // agent UUID -> *def.AgentToken

// StoreAgentToken records the current AgentToken issued to an agent.
func StoreAgentToken(uuid string, tok *def.AgentToken) {
	if uuid == "" || tok == nil {
		return
	}
	agentTokens.Store(uuid, tok)
}

// AgentTokenFor returns the current AgentToken issued to an agent, or nil if
// the agent has not been issued one (or it was never cached).
func AgentTokenFor(uuid string) *def.AgentToken {
	if uuid == "" {
		return nil
	}
	v, ok := agentTokens.Load(uuid)
	if !ok {
		return nil
	}
	tok, _ := v.(*def.AgentToken)
	return tok
}
