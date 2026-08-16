package server

import (
	"sync/atomic"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestAgentCommandQueue(t *testing.T) {
	const uuid = "test-queue-uuid"
	agentCommandQueues.Delete(uuid)

	if hasQueuedCommands(uuid) {
		t.Fatal("unexpected queued commands for empty queue")
	}

	enqueueAgentCommand(uuid, def.MsgTunData{JobID: "1"})
	enqueueAgentCommand(uuid, def.MsgTunData{JobID: "2"})
	if !hasQueuedCommands(uuid) {
		t.Fatal("expected queued commands after enqueue")
	}

	cmds := dequeueAgentCommands(uuid, 1)
	if len(cmds) != 1 || cmds[0].JobID != "1" {
		t.Fatalf("unexpected first dequeue: %v", cmds)
	}
	if !hasQueuedCommands(uuid) {
		t.Fatal("expected remaining queued command")
	}

	cmds = dequeueAgentCommands(uuid, 0)
	if len(cmds) != 1 || cmds[0].JobID != "2" {
		t.Fatalf("unexpected dequeue-all: %v", cmds)
	}
	if hasQueuedCommands(uuid) {
		t.Fatal("expected empty queue after dequeue-all")
	}
}

func TestOperatorIsActive(t *testing.T) {
	oldTimeout := live.RuntimeConfig.OperatorIdleTimeout
	defer func() { live.RuntimeConfig.OperatorIdleTimeout = oldTimeout }()

	if operatorOnline() {
		t.Fatal("expected no operator to be online before test setup")
	}

	OPERATORS.Store("test-operator", &operator_t{sessionID: "test-operator"})
	defer OPERATORS.Delete("test-operator")

	live.RuntimeConfig.OperatorIdleTimeout = 1
	atomic.StoreInt64(&lastOperatorCommand, 0)
	if operatorIsActive() {
		t.Fatal("expected operator to be inactive before first command")
	}

	touchOperatorCommand()
	if !operatorIsActive() {
		t.Fatal("expected operator to be active after touchOperatorCommand")
	}

	live.RuntimeConfig.OperatorIdleTimeout = 0
	if !operatorIsActive() {
		t.Fatal("expected operator to be active when idle timeout is disabled")
	}

	OPERATORS.Delete("test-operator")
	if operatorIsActive() {
		t.Fatal("expected operator to be inactive when offline")
	}
}
