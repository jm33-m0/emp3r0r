package server

import (
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// shouldAdmitAgentForMsg decides whether an agent's message-tunnel connection
// should be admitted. While the operator is active the connection is always
// admitted; otherwise it is admitted only when the agent has queued commands.
func shouldAdmitAgentForMsg(agentUUID string) bool {
	if operatorIsActive() {
		return true
	}
	return hasQueuedCommands(agentUUID)
}

// agentCommandQueue is a per-agent FIFO of MsgTunData commands awaiting a live
// message tunnel.
type agentCommandQueue struct {
	mu   sync.Mutex
	cmds []def.MsgTunData
}

// agentCommandQueues maps agent UUID to its pending command queue.
var agentCommandQueues sync.Map // agentUUID -> *agentCommandQueue

// enqueueAgentCommand appends a command to an agent's pending queue.
func enqueueAgentCommand(agentUUID string, msg def.MsgTunData) {
	if agentUUID == "" {
		return
	}
	val, _ := agentCommandQueues.LoadOrStore(agentUUID, &agentCommandQueue{})
	q := val.(*agentCommandQueue)
	q.mu.Lock()
	q.cmds = append(q.cmds, msg)
	depth := len(q.cmds)
	q.mu.Unlock()
	logging.Infof("Queued command %s for agent %s (queue depth %d)", msg.JobID, agentUUID, depth)
}

// hasQueuedCommands reports whether an agent has at least one pending command.
func hasQueuedCommands(agentUUID string) bool {
	if agentUUID == "" {
		return false
	}
	val, ok := agentCommandQueues.Load(agentUUID)
	if !ok {
		return false
	}
	q := val.(*agentCommandQueue)
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.cmds) > 0
}

// dequeueAgentCommands removes and returns up to max commands for an agent.
// A max <= 0 returns all pending commands.
func dequeueAgentCommands(agentUUID string, max int) []def.MsgTunData {
	val, ok := agentCommandQueues.Load(agentUUID)
	if !ok {
		return nil
	}
	q := val.(*agentCommandQueue)
	q.mu.Lock()
	defer q.mu.Unlock()
	if max <= 0 || max > len(q.cmds) {
		max = len(q.cmds)
	}
	out := make([]def.MsgTunData, max)
	copy(out, q.cmds[:max])
	q.cmds = q.cmds[max:]
	if len(q.cmds) == 0 {
		agentCommandQueues.Delete(agentUUID)
	}
	return out
}

// requeueAgentCommands prepends commands back onto an agent's queue (used when
// delivery fails partway through so no queued command is lost).
func requeueAgentCommands(agentUUID string, cmds []def.MsgTunData) {
	if len(cmds) == 0 {
		return
	}
	val, _ := agentCommandQueues.LoadOrStore(agentUUID, &agentCommandQueue{})
	q := val.(*agentCommandQueue)
	q.mu.Lock()
	q.cmds = append(cmds, q.cmds...)
	q.mu.Unlock()
}

// drainQueuedCommands writes all pending commands for an agent to the given
// encoder. Commands that could not be written are requeued.
func drainQueuedCommands(agentUUID string, encoder *cbor.Encoder) {
	cmds := dequeueAgentCommands(agentUUID, 0)
	for i, cmd := range cmds {
		if err := encoder.Encode(cmd); err != nil {
			logging.Warningf("drainQueuedCommands: send %s to %s failed: %v", cmd.JobID, agentUUID, err)
			requeueAgentCommands(agentUUID, cmds[i:])
			return
		}
		logging.Infof("Delivered queued command %s to agent %s", cmd.JobID, agentUUID)
	}
}
