//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/libbpf"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// withFakeUprobeRunner replaces the capture seam for one test and restores it
// afterwards. Tests that need to inspect the options the session built can keep
// a reference to the returned pointer.
func withFakeUprobeRunner(t *testing.T, runner func(libbpf.UprobeCapture) error) *libbpf.UprobeCapture {
	t.Helper()
	saved := runUprobeCapture
	var got libbpf.UprobeCapture
	var mu sync.Mutex
	wrapped := func(opts libbpf.UprobeCapture) error {
		mu.Lock()
		got = opts
		mu.Unlock()
		return runner(opts)
	}
	runUprobeCapture = wrapped
	t.Cleanup(func() {
		runUprobeCapture = saved
		stopAllUprobeSessions()
	})
	return &got
}

// stopAllUprobeSessions cancels every live session and waits for teardown so a
// failing test cannot leak goroutines into the next one.
func stopAllUprobeSessions() {
	var sessions []*uprobeSession
	uprobeSessionsMu.Lock()
	uprobeSessions.Range(func(_, v any) bool {
		sessions = append(sessions, v.(*uprobeSession))
		return true
	})
	uprobeSessionsMu.Unlock()
	for _, s := range sessions {
		s.cancel()
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
		}
		uprobeSessionsMu.Lock()
		uprobeSessions.Delete(s.id)
		uprobeSessionsMu.Unlock()
	}
}

func testUprobeConfig(owner, outPath string, emits []libbpf.UprobeEvent) uprobeStartConfig {
	return uprobeStartConfig{
		owner:   owner,
		image:   []byte("BPFfake-object"),
		path:    "/usr/sbin/sshd",
		offset:  0x1234,
		prog:    "probe",
		reg:     "RSI",
		pid:     -1,
		outPath: outPath,
	}
}

// TestUprobeSessionLifecycle starts a session with a fake capture, checks that
// events are persisted to memfs and streamed through the notifier, then stops
// it and checks the collected events and registry cleanup.
func TestUprobeSessionLifecycle(t *testing.T) {
	const outPath = "memfs:///uprobe_session_lifecycle.log"
	defer util.RemoveFileAgent(outPath)

	notified := make(chan string, 8)
	runner := func(opts libbpf.UprobeCapture) error {
		if opts.OnAttached != nil {
			opts.OnAttached()
		}
		opts.OnEvent(libbpf.UprobeEvent{PID: 11, UID: 0, Retval: 1, Comm: "sshd", Arg: "hunter2"})
		opts.OnEvent(libbpf.UprobeEvent{PID: 12, UID: 1000, Retval: 0, Comm: "sshd", Arg: "nope"})
		<-opts.Stop
		return nil
	}
	got := withFakeUprobeRunner(t, runner)

	cfg := testUprobeConfig("testmod", outPath, nil)
	cfg.notify = func(msg string) { notified <- msg }
	s, err := startUprobeSession(cfg)
	if err != nil {
		t.Fatalf("startUprobeSession: %v", err)
	}
	if s.outPath != outPath || s.id == "" {
		t.Fatalf("session = %+v, want outPath %q and a non-empty id", s, outPath)
	}
	if !got.UntilStopped {
		t.Fatalf("timeout_ms=0 session should run until stopped: %+v", got)
	}

	// Both events are emitted (and written to memfs) before the runner blocks
	// on Stop, so draining the notification channel first makes the file read
	// race-free.
	first := <-notified
	second := <-notified
	if !strings.Contains(first, `arg="hunter2"`) || !strings.Contains(second, `arg="nope"`) {
		t.Fatalf("notified %q, %q; want the two event lines", first, second)
	}
	content, err := util.ReadFileAgent(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(content), `arg="hunter2"`) {
		t.Fatalf("output file missing first event:\n%s", content)
	}

	sessions, err := stopUprobeSessions("", "testmod")
	if err != nil {
		t.Fatalf("stopUprobeSessions: %v", err)
	}
	if len(sessions) != 1 || len(sessions[0].events) != 2 {
		t.Fatalf("stop returned %d sessions with %d events, want 1 with 2", len(sessions), len(sessions[0].events))
	}
	if sessions[0].outPath != outPath {
		t.Fatalf("stopped outPath = %q, want %q", sessions[0].outPath, outPath)
	}
	if _, ok := uprobeSessions.Load(s.id); ok {
		t.Fatal("session still registered after stop")
	}
}

// TestUprobeSessionOnePerOwner rejects a second live capture for the same owner
// and allows a fresh one once the first has been stopped.
func TestUprobeSessionOnePerOwner(t *testing.T) {
	runner := func(opts libbpf.UprobeCapture) error {
		if opts.OnAttached != nil {
			opts.OnAttached()
		}
		<-opts.Stop
		return nil
	}
	withFakeUprobeRunner(t, runner)

	const outPath = "memfs:///uprobe_session_owner.log"
	defer util.RemoveFileAgent(outPath)

	first, err := startUprobeSession(testUprobeConfig("ownermod", outPath, nil))
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if _, err := startUprobeSession(testUprobeConfig("ownermod", outPath, nil)); err == nil {
		t.Fatal("second start for the same owner succeeded, want an error")
	}
	if _, err := stopUprobeSessions("", "ownermod"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, ok := uprobeSessions.Load(first.id); ok {
		t.Fatal("first session still registered after stop")
	}
	second, err := startUprobeSession(testUprobeConfig("ownermod", outPath, nil))
	if err != nil {
		t.Fatalf("restart after stop: %v", err)
	}
	if _, err := stopUprobeSessions("", "ownermod"); err != nil {
		t.Fatalf("stop second: %v", err)
	}
	_ = second
}

// TestUprobeSessionAttachFailure reports the attach error to the caller and
// leaves no session behind, so a missing dependency is visible immediately.
func TestUprobeSessionAttachFailure(t *testing.T) {
	withFakeUprobeRunner(t, func(libbpf.UprobeCapture) error {
		return fmt.Errorf("boom")
	})

	if _, err := startUprobeSession(testUprobeConfig("failmod", "memfs:///uprobe_session_fail.log", nil)); err == nil {
		t.Fatal("start succeeded despite the capture error")
	}
	found := false
	uprobeSessions.Range(func(_, v any) bool {
		if v.(*uprobeSession).owner == "failmod" {
			found = true
		}
		return true
	})
	if found {
		t.Fatal("failed session left registered")
	}
}

// TestUprobeSessionReplacesFinishedSession lets a module start a new capture
// after a previous one ended on its own (timeout), without an explicit stop.
func TestUprobeSessionReplacesFinishedSession(t *testing.T) {
	const outPath = "memfs:///uprobe_session_finished.log"
	defer util.RemoveFileAgent(outPath)

	withFakeUprobeRunner(t, func(opts libbpf.UprobeCapture) error {
		if opts.OnAttached != nil {
			opts.OnAttached()
		}
		opts.OnEvent(libbpf.UprobeEvent{PID: 1, UID: 0, Retval: 1, Comm: "sshd", Arg: "old"})
		return nil // ends immediately, like a timed-out capture
	})

	first, err := startUprobeSession(testUprobeConfig("finmod", outPath, nil))
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	// Wait for the runner to finish.
	select {
	case <-first.done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not finish")
	}
	second, err := startUprobeSession(testUprobeConfig("finmod", outPath, nil))
	if err != nil {
		t.Fatalf("restart after finished session: %v", err)
	}
	if second.id == first.id {
		t.Fatal("restart reused the finished session id")
	}
	if _, err := stopUprobeSessions("", "finmod"); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// TestUprobeStartTimeoutIsForwarded pins the timeout_ms plumbing: a non-zero
// timeout is a finite capture, while zero means until stopped.
func TestUprobeStartTimeoutIsForwarded(t *testing.T) {
	got := withFakeUprobeRunner(t, func(opts libbpf.UprobeCapture) error {
		if opts.OnAttached != nil {
			opts.OnAttached()
		}
		<-opts.Stop
		return nil
	})

	cfg := testUprobeConfig("timemod", "memfs:///uprobe_session_time.log", nil)
	cfg.timeoutMS = 2500
	s, err := startUprobeSession(cfg)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if got.UntilStopped {
		t.Fatal("finite timeout reported UntilStopped")
	}
	if got.Timeout != 2500*time.Millisecond {
		t.Fatalf("Timeout = %v, want 2.5s", got.Timeout)
	}
	if _, err := stopUprobeSessions("", "timemod"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	_ = s
}
