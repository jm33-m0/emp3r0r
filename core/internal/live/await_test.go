package live

import (
	"errors"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// withRuntimeConfig installs cfg for one test and restores the previous one.
func withRuntimeConfig(t *testing.T, cfg *def.Config) {
	t.Helper()
	prev := GetRuntimeConfig()
	t.Cleanup(func() { SetRuntimeConfig(prev) })
	SetRuntimeConfig(cfg)
}

func TestAgentReplyTimeoutCoversPollInterval(t *testing.T) {
	withRuntimeConfig(t, &def.Config{PollInterval: 60, PollWindow: 5, Jitter: 10})

	// One polled interval with its jitter, the command window, and the slack.
	want := time.Duration(60*110/100+5)*time.Second + replySlack
	if got := AgentReplyTimeout(); got != want {
		t.Errorf("AgentReplyTimeout = %s, want %s", got, want)
	}

	// An unset interval falls back to the same default the agent uses.
	withRuntimeConfig(t, &def.Config{})
	if got := AgentReplyTimeout(); got < 60*time.Second {
		t.Errorf("AgentReplyTimeout without a configured interval = %s, want at least one default poll interval", got)
	}
}

func TestAwaitCmdResultDeliversReply(t *testing.T) {
	CmdResults.Clear()
	CmdResultsReady.Clear()

	jobID := "await-delivers"
	var registeredBeforeSend bool
	res, err := AwaitCmdResult(jobID, time.Second, func() error {
		_, registeredBeforeSend = CmdResultsReady.Load(jobID)
		go func() {
			CmdResults.Store(jobID, "payload")
			SignalCmdResultReady(jobID)
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("AwaitCmdResult: %v", err)
	}
	if !registeredBeforeSend {
		t.Error("the waiter was not registered before the command was sent")
	}
	if res != "payload" {
		t.Errorf("result = %q, want payload", res)
	}
	if _, ok := CmdResultsReady.Load(jobID); ok {
		t.Error("the waiter registration was not dropped")
	}
	if _, ok := CmdResults.Load(jobID); ok {
		t.Error("the cached result was not consumed")
	}
}

func TestAwaitCmdResultTimesOut(t *testing.T) {
	CmdResultsReady.Clear()

	jobID := "await-times-out"
	start := time.Now()
	if _, err := AwaitCmdResult(jobID, 20*time.Millisecond, func() error { return nil }); err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %s, want the requested 20ms", elapsed)
	}
	if _, ok := CmdResultsReady.Load(jobID); ok {
		t.Error("the waiter registration was not dropped after the timeout")
	}
}

func TestAwaitCmdResultSendError(t *testing.T) {
	CmdResultsReady.Clear()

	jobID := "await-send-error"
	sendErr := errors.New("agent is offline")
	_, err := AwaitCmdResult(jobID, time.Second, func() error { return sendErr })
	if !errors.Is(err, sendErr) {
		t.Errorf("err = %v, want the send error", err)
	}
	if _, ok := CmdResultsReady.Load(jobID); ok {
		t.Error("the waiter registration was not dropped after a send failure")
	}
}

// TestAwaitCmdResultUsesCachedResult covers a caller that dispatches first and
// waits afterwards: the result is already cached, so the waiter must not wait
// for a notification that was never sent.
func TestAwaitCmdResultUsesCachedResult(t *testing.T) {
	CmdResults.Clear()
	CmdResultsReady.Clear()

	jobID := "await-cached"
	CmdResults.Store(jobID, "early")
	sent := false
	res, err := AwaitCmdResult(jobID, time.Second, func() error {
		sent = true
		return nil
	})
	if err != nil {
		t.Fatalf("AwaitCmdResult: %v", err)
	}
	if sent {
		t.Error("a cached result must not re-send the command")
	}
	if res != "early" {
		t.Errorf("result = %q, want early", res)
	}
	if _, ok := CmdResults.Load(jobID); ok {
		t.Error("the cached result was not consumed")
	}
}

// TestAwaitCmdResultLateReply covers a reply that lands while the waiter is
// already gone: the result must stay cached for whoever looks next, and no
// registration may be left behind.
func TestAwaitCmdResultLateReply(t *testing.T) {
	CmdResults.Clear()
	CmdResultsReady.Clear()

	jobID := "await-late"
	if _, err := AwaitCmdResult(jobID, 10*time.Millisecond, func() error { return nil }); err == nil {
		t.Fatal("expected a timeout")
	}

	CmdResults.Store(jobID, "late")
	SignalCmdResultReady(jobID) // no registration left: must not panic
	if res, ok := CmdResultString(jobID); !ok || res != "late" {
		t.Errorf("late result = %q (cached=%v), want it kept for a later reader", res, ok)
	}
	CmdResults.Delete(jobID)
}

// TestAwaitCmdResultDefaultTimeout checks that a caller can rely on the shared
// policy instead of picking a constant.
func TestAwaitCmdResultDefaultTimeout(t *testing.T) {
	CmdResults.Clear()
	CmdResultsReady.Clear()

	prevSlack := replySlack
	replySlack = 100 * time.Millisecond
	t.Cleanup(func() { replySlack = prevSlack })
	withRuntimeConfig(t, &def.Config{PollInterval: 1, PollWindow: 0})

	start := time.Now()
	if _, err := AwaitCmdResult("await-default", 0, func() error { return nil }); err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("default timeout fired after %s, want at least one poll interval", elapsed)
	}
}
