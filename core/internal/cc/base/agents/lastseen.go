package agents

import (
	"crypto/sha1"
	"fmt"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// agentLastSeen and agentLastSeenRTT keep the frequently-updated agent
// liveness fields out of the shared *def.Emp3r0rAgent objects.
//
// The message-tunnel goroutine mutates these values on every authenticated
// frame, while the operator-facing agent list (handleListAgents) and the
// enriched-peer-list builder read them. Storing them in sync.Map lets both
// sides access the latest value without a data race.
var (
	agentLastSeen    sync.Map // agent UUID -> time.Time
	agentLastSeenRTT sync.Map // agent UUID -> time.Duration
)

// MarkAgentSeen records that the agent has been seen at seenAt.
func MarkAgentSeen(agent *def.Emp3r0rAgent, seenAt time.Time) {
	if agent == nil || agent.UUID == "" {
		return
	}
	agentLastSeen.Store(agent.UUID, seenAt)
}

// MarkAgentSeenByUUID records a last-seen time for an agent UUID.
func MarkAgentSeenByUUID(uuid string, seenAt time.Time) {
	if uuid == "" {
		return
	}
	agentLastSeen.Store(uuid, seenAt)
}

// AgentLastSeen returns the last-seen time recorded for an agent UUID.
func AgentLastSeen(uuid string) (time.Time, bool) {
	if uuid == "" {
		return time.Time{}, false
	}
	val, ok := agentLastSeen.Load(uuid)
	if !ok {
		return time.Time{}, false
	}
	seenAt, ok := val.(time.Time)
	if !ok {
		return time.Time{}, false
	}
	return seenAt, true
}

// MarkAgentRTT records the last measured round-trip time for an agent.
func MarkAgentRTT(agent *def.Emp3r0rAgent, rtt time.Duration) {
	if agent == nil || agent.UUID == "" {
		return
	}
	agentLastSeenRTT.Store(agent.UUID, rtt)
}

// AgentLastSeenRTT returns the last measured round-trip time for an agent UUID.
func AgentLastSeenRTT(uuid string) (time.Duration, bool) {
	if uuid == "" {
		return 0, false
	}
	val, ok := agentLastSeenRTT.Load(uuid)
	if !ok {
		return 0, false
	}
	rtt, ok := val.(time.Duration)
	if !ok {
		return 0, false
	}
	return rtt, true
}

// SnapshotAgent returns a copy of a with the synchronized LastSeen/RTT values.
// Callers that need to serialize or display an agent without racing the
// message-tunnel goroutine should use this copy instead of the shared pointer.
func SnapshotAgent(a *def.Emp3r0rAgent) *def.Emp3r0rAgent {
	if a == nil {
		return nil
	}
	cp := *a
	if cp.ShortID == "" && cp.UUID != "" {
		shortID := fmt.Sprintf("%x", sha1.Sum([]byte(cp.UUID+cp.UUIDSig)))
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		cp.ShortID = shortID
	}
	if seenAt, ok := AgentLastSeen(a.UUID); ok {
		cp.LastSeen = seenAt
	}
	if rtt, ok := AgentLastSeenRTT(a.UUID); ok {
		cp.LastSeenRTT = rtt
	}
	return &cp
}
