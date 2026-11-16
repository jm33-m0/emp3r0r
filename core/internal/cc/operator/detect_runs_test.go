package operator

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
)

func fakeDetectRun(t *testing.T, id string) (*detectRun, *detection.OperatorPromptQueue) {
	t.Helper()
	resetDetectRunsForTest()
	prompts := detection.NewOperatorPromptQueue()
	run, err := registerDetectRun(id, prompts, "/tmp/loop.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-run.ctx.Done()
		run.finish()
	}()
	t.Cleanup(func() {
		run.cancel()
		resetDetectRunsForTest()
	})
	return run, prompts
}

func TestDetectRunRegistryStopsAndPrompts(t *testing.T) {
	id := "loop-20261116-130000"
	run, prompts := fakeDetectRun(t, id)
	if info := run.info(); info.Status != "running" {
		t.Fatalf("status = %q", info.Status)
	}
	info, err := appendDetectRunPrompt(id, "focus on module overloading")
	if err != nil {
		t.Fatal(err)
	}
	if info.Prompts != 1 || prompts.Len() != 1 {
		t.Fatalf("prompts = %+v len=%d", info, prompts.Len())
	}
	if drained := prompts.Drain(); len(drained) != 1 || drained[0] != "focus on module overloading" {
		t.Fatalf("drained = %#v", drained)
	}
	info, wasRunning, err := stopDetectRun(id, time.Second)
	if err != nil || !wasRunning {
		t.Fatalf("stop = %+v running=%v err=%v", info, wasRunning, err)
	}
	select {
	case <-run.done:
	case <-time.After(time.Second):
		t.Fatal("run did not finish after stop")
	}
	if got := run.info(); got.Status != "stopped" {
		t.Fatalf("status after stop = %q", got.Status)
	}
	if _, _, err := stopDetectRun("loop-20261116-999999", 0); err == nil {
		t.Fatal("stopping an unknown loop must fail")
	}
}

func TestDetectRunRegistryRejectsDuplicateID(t *testing.T) {
	id := "loop-20261116-130001"
	_, _ = fakeDetectRun(t, id)
	if _, err := registerDetectRun(id, detection.NewOperatorPromptQueue(), "/tmp/loop.log", nil); err == nil {
		t.Fatal("duplicate loop id was accepted")
	}
}

func TestDetectLoopManagementCommands(t *testing.T) {
	id := "loop-20261116-130002"
	_, prompts := fakeDetectRun(t, id)

	runCommand := func(args ...string) string {
		cmd := detectLoopCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("detect_loop %v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}

	if out := runCommand("list", "--json"); !strings.Contains(out, id) {
		t.Fatalf("list output = %q", out)
	}
	runCommand("prompt", id, "focus on module overloading")
	if prompts.Len() != 1 {
		t.Fatalf("prompt queue len = %d", prompts.Len())
	}
	runCommand("stop", id)
	if got := findDetectRun(id); got == nil || got.info().Status != "stopped" {
		t.Fatalf("run after stop = %+v", got)
	}
}
