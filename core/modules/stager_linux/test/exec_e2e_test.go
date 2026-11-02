//go:build linux && cgo

package shellcode_stager

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// runExecChecks drives the operator `exec` command against a C agent. The
// controller routes it to the exec BOF, the agent runs the command in a child
// process and the BOF's captured output comes back as the job result.
func runExecChecks(t *testing.T, agent *def.Emp3r0rAgent, agentOut *bytes.Buffer) {
	t.Helper()

	coreDir, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve core dir: %v", err)
	}
	// The module dispatcher builds and hosts the payload from the real
	// manifests; the console injects CmdSender.
	live.ModuleDirs = []string{filepath.Join(coreDir, "modules")}
	modules.InitModules()
	prevSender := modules.CmdSender
	modules.CmdSender = controllers.ExecuteCommand
	t.Cleanup(func() { modules.CmdSender = prevSender })

	exec := func(t *testing.T, command string, noShell bool) string {
		t.Helper()
		flags := map[string]string{
			"cmd_to_exec": fmt.Sprintf("exec --cmd %q", command),
			"exec_cmd":    command,
		}
		if noShell {
			flags["exec_shell"] = "0"
		}
		ctx := &c2context.C2Context{Target: agent, Flags: flags}
		controllers.ExecuteRawCommand(ctx)

		job := latestExecJob(agent.Tag, command)
		if job == nil {
			t.Fatalf("exec %q did not create a job\nAgent output:\n%s", command, agentOut.String())
		}
		out, err := live.AwaitCmdResult(job.ID, 90*time.Second, func() error { return nil })
		if err != nil {
			t.Fatalf("exec %q: %v\nAgent output:\n%s", command, err, agentOut.String())
		}
		return out
	}

	t.Run("exec-runs-a-command", func(t *testing.T) {
		out := exec(t, "echo emp3r0r-exec-ok", false)
		if !strings.Contains(out, "emp3r0r-exec-ok") {
			t.Fatalf("exec output = %q, want the command's stdout\nAgent output:\n%s", out, agentOut.String())
		}
	})

	// stderr is captured on the same pipe, so a failing command's reason still
	// reaches the operator.
	t.Run("exec-captures-stderr", func(t *testing.T) {
		out := exec(t, "echo emp3r0r-stderr-ok >&2", false)
		if !strings.Contains(out, "emp3r0r-stderr-ok") {
			t.Fatalf("exec output = %q, want the command's stderr\nAgent output:\n%s", out, agentOut.String())
		}
	})

	// The default mode runs through /bin/sh: the arithmetic expansion happens.
	t.Run("exec-shellexpands", func(t *testing.T) {
		out := exec(t, "echo $((40+2))", false)
		if !strings.Contains(out, "42") {
			t.Fatalf("exec output = %q, want the shell to expand $((40+2))\nAgent output:\n%s", out, agentOut.String())
		}
	})

	// --no-shell execs the tokenized command directly: no expansion, and quotes
	// still group words.
	t.Run("exec-no-shell-is-direct", func(t *testing.T) {
		out := exec(t, "echo $((40+2)) 'two  spaces'", true)
		if strings.Contains(out, "42") {
			t.Fatalf("exec output = %q, want $((40+2)) literal without a shell\nAgent output:\n%s", out, agentOut.String())
		}
		if !strings.Contains(out, "$((40+2))") || !strings.Contains(out, "two  spaces") {
			t.Fatalf("exec output = %q, want the literal argument and the quoted word\nAgent output:\n%s", out, agentOut.String())
		}
	})
}

// latestExecJob returns the most recent `command` job dispatched to tag.
func latestExecJob(tag, name string) *def.Job {
	var latest *def.Job
	for _, job := range jobs.GetJobs() {
		if job == nil || job.AgentTag != tag || job.Name != name {
			continue
		}
		if latest == nil || job.Created.After(latest.Created) {
			latest = job
		}
	}
	return latest
}
