package server

import (
	"sync"
	"time"
)

// agentLock records which operator owns an agent. Values stored in agentLocks
// are immutable snapshots: writers publish a fresh lock with Store or
// CompareAndSwap instead of mutating a published one, so readers never race.
type agentLock struct {
	OperatorID   string
	OperatorName string
	Since        time.Time
	LastRenewed  time.Time
}

// agentLocks maps an agent UUID to its *agentLock.
var agentLocks sync.Map

// operatorLockTimeout bounds how long a lock survives without renewal while the
// operator session is still connected, so an idle operator eventually releases
// its agents. It reuses the operator idle timeout and falls back to a fixed
// window when idle-based rejection is disabled.
func operatorLockTimeout() time.Duration {
	timeout := currentOperatorIdleTimeout()
	if timeout <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(timeout) * time.Second
}

// lockExpired reports whether a lock may be reclaimed: its owner session is
// gone, or it has not been renewed within the timeout.
func lockExpired(lock *agentLock, now time.Time) bool {
	if lock == nil {
		return true
	}
	if !operatorSessionOnline(lock.OperatorID) {
		return true
	}
	return now.Sub(lock.LastRenewed) > operatorLockTimeout()
}

// acquireAgentLock locks agentUUID for the calling operator, renewing the lock
// when that same operator already owns it. It reports whether the caller now
// owns the agent; on failure it also returns the current owner's display name.
// A live lock held by another operator is never stolen.
func acquireAgentLock(agentUUID, operatorID, operatorName string) (acquired bool, heldBy string) {
	if agentUUID == "" || operatorID == "" {
		return false, ""
	}
	now := time.Now()
	for {
		candidate := &agentLock{
			OperatorID:   operatorID,
			OperatorName: operatorName,
			Since:        now,
			LastRenewed:  now,
		}
		actual, loaded := agentLocks.LoadOrStore(agentUUID, candidate)
		if !loaded {
			return true, ""
		}

		lock, ok := actual.(*agentLock)
		if !ok || lock == nil {
			// Replace an unexpected value instead of panicking on the assertion.
			if agentLocks.CompareAndSwap(agentUUID, actual, candidate) {
				return true, ""
			}
			continue
		}
		if lock.OperatorID == operatorID {
			candidate.Since = lock.Since
			agentLocks.Store(agentUUID, candidate)
			return true, ""
		}
		if lockExpired(lock, now) {
			if agentLocks.CompareAndSwap(agentUUID, lock, candidate) {
				return true, ""
			}
			// Another operator reclaimed it first; retry against the new lock.
			continue
		}
		return false, lock.OperatorName
	}
}

// releaseAgentLocksForOperator drops every lock held by operatorID. It is used
// when an operator switches target, disconnects or times out.
func releaseAgentLocksForOperator(operatorID string) {
	if operatorID == "" {
		return
	}
	agentLocks.Range(func(k, v any) bool {
		lock, ok := v.(*agentLock)
		if ok && lock != nil && lock.OperatorID == operatorID {
			agentLocks.CompareAndDelete(k, lock)
		}
		return true
	})
}

// renewAgentLocksForOperator refreshes the lease on every lock held by
// operatorID. The C2 calls it for any authenticated operator request, so a
// live operator keeps its claims while reading output and only loses them when
// it actually stops talking to the C2.
func renewAgentLocksForOperator(operatorID string) {
	if operatorID == "" {
		return
	}
	now := time.Now()
	agentLocks.Range(func(k, v any) bool {
		lock, ok := v.(*agentLock)
		if !ok || lock == nil || lock.OperatorID != operatorID {
			return true
		}
		renewed := *lock
		renewed.LastRenewed = now
		agentLocks.CompareAndSwap(k, lock, &renewed)
		return true
	})
}

// releaseAgentLocksForOperatorExcept drops every lock held by operatorID except
// keepAgentUUID. A target switch uses it after the new claim succeeds, so a
// rejected switch never drops the operator's current target.
func releaseAgentLocksForOperatorExcept(operatorID, keepAgentUUID string) {
	if operatorID == "" {
		return
	}
	agentLocks.Range(func(k, v any) bool {
		lock, ok := v.(*agentLock)
		if !ok || lock == nil || lock.OperatorID != operatorID {
			return true
		}
		if uuid, ok := k.(string); ok && uuid == keepAgentUUID {
			return true
		}
		agentLocks.CompareAndDelete(k, lock)
		return true
	})
}

// deleteAgentLock unconditionally removes an agent's lock. It is used when the
// agent is forgotten, so a future re-check-in is not blocked by a stale lock.
func deleteAgentLock(agentUUID string) {
	if agentUUID != "" {
		agentLocks.Delete(agentUUID)
	}
}

// agentLockOwner returns the name of the operator holding agentUUID, or "" when
// the agent is free or its lock has expired.
func agentLockOwner(agentUUID string) string {
	actual, ok := agentLocks.Load(agentUUID)
	if !ok {
		return ""
	}
	lock, ok := actual.(*agentLock)
	if !ok || lock == nil || lockExpired(lock, time.Now()) {
		return ""
	}
	return lock.OperatorName
}

// agentLockOwnerSession returns the operator identity (WireGuard IP) holding
// agentUUID, or "" when the agent is free or its lock has expired. Callers that
// must route work to the operator controlling an agent use this instead of the
// display name.
func agentLockOwnerSession(agentUUID string) string {
	actual, ok := agentLocks.Load(agentUUID)
	if !ok {
		return ""
	}
	lock, ok := actual.(*agentLock)
	if !ok || lock == nil || lockExpired(lock, time.Now()) {
		return ""
	}
	return lock.OperatorID
}
