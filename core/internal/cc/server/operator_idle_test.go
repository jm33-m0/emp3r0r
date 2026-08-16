package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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

func TestOperatorIdleNotificationAndResume(t *testing.T) {
	oldTimeout := live.RuntimeConfig.OperatorIdleTimeout
	defer func() { live.RuntimeConfig.OperatorIdleTimeout = oldTimeout }()

	operatorIdleNotified.Store(false)
	OPERATORS.Delete("test-operator")

	opClient, opServer := net.Pipe()
	defer opClient.Close()
	defer opServer.Close()
	OPERATORS.Store("test-operator", &operator_t{sessionID: "test-operator", conn: opServer})
	defer OPERATORS.Delete("test-operator")

	received := make(chan def.MsgTunData, 4)
	go func() {
		dec := cbor.NewDecoder(opClient)
		for {
			var msg def.MsgTunData
			if err := dec.Decode(&msg); err != nil {
				return
			}
			received <- msg
		}
	}()

	live.RuntimeConfig.OperatorIdleTimeout = 60

	maybeNotifyOperatorIdle()
	maybeNotifyOperatorIdle() // duplicate must be suppressed

	select {
	case msg := <-received:
		if msg.Tag != logging.WARN {
			t.Fatalf("expected WARN notification, got %q", msg.Tag)
		}
		if !strings.Contains(string(msg.Response), "resume") {
			t.Fatalf("expected resume hint in notification, got %q", msg.Response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for idle notification")
	}

	select {
	case msg := <-received:
		t.Fatalf("unexpected duplicate idle notification: %#v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	operatorIdleNotified.Store(true)
	touchOperatorCommand()

	select {
	case msg := <-received:
		if msg.Tag != logging.SUCCESS {
			t.Fatalf("expected SUCCESS resume notification, got %q", msg.Tag)
		}
		if !strings.Contains(string(msg.Response), "Operator active again") {
			t.Fatalf("unexpected resume notification: %q", msg.Response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for resume notification")
	}

	if operatorIdleNotified.Load() {
		t.Fatal("operatorIdleNotified was not cleared after resume")
	}
}

func TestHandleResumeOperator(t *testing.T) {
	atomic.StoreInt64(&lastOperatorCommand, 0)
	req := httptest.NewRequest(http.MethodPost, "/operator/resume", nil)
	rec := httptest.NewRecorder()

	handleResumeOperator(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if atomic.LoadInt64(&lastOperatorCommand) == 0 {
		t.Fatal("expected handleResumeOperator to touch operator command timer")
	}
}
