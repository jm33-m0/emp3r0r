package detection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestAgentSourceEditMarksDirty(t *testing.T) {
	base := t.TempDir()
	agentDir := filepath.Join(base, "go_agent")
	moduleDir := filepath.Join(base, "modules", "loader_windows")
	for _, dir := range []string{agentDir, moduleDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(agentDir, "agent.go"), filepath.Join(moduleDir, "loader.c")} {
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	roots, err := newSourceRoots("loader_windows",
		sourceRoot{Name: "loader_windows", Dir: moduleDir, Writable: true},
		sourceRoot{Name: "go_agent", Dir: agentDir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			AgentSourceDir: agentDir, Platform: platformWindows, Iterations: 20,
		},
		db: db, roots: roots, logf: func(logging.Class, string, ...any) {},
	}
	if got := callTool(t, e, "EditSource", map[string]any{
		"module": "go_agent", "file": "agent.go", "old_string": "old", "new_string": "new",
	}); got.isError {
		t.Fatalf("agent edit failed: %s", got.text)
	}
	if !e.agentSourceDirty.Load() {
		t.Fatal("agent source edit did not mark the agent dirty")
	}
	e.agentSourceDirty.Store(false)
	if got := callTool(t, e, "EditSource", map[string]any{
		"module": "loader_windows", "file": "loader.c", "old_string": "old", "new_string": "new",
	}); got.isError {
		t.Fatalf("module edit failed: %s", got.text)
	}
	if e.agentSourceDirty.Load() {
		t.Fatal("module edit marked the agent dirty")
	}
}

func TestPendingAgentStateForcesRotation(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*evolver)
	}{
		{name: "dirty source", setup: func(e *evolver) { e.agentSourceDirty.Store(true) }},
		{name: "unwrapped agent", setup: func(e *evolver) { e.agentNeedsWrap.Store(true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			e := &evolver{
				shellcode: "fresh.bin",
				cfg: EvolveConfig{
					LoopID: "loop", Module: "loader_windows",
					BuildAgent: func(AgentBuildOptions) (*AgentBuildResult, error) {
						called = true
						return nil, errors.New("stop after rotation")
					},
				},
				logf: func(logging.Class, string, ...any) {},
			}
			tc.setup(e)
			if err := e.ensureFreshAgent(context.Background()); err == nil {
				t.Fatal("ensureFreshAgent returned nil instead of attempting rotation")
			}
			if !called {
				t.Fatal("ensureFreshAgent did not attempt an agent rebuild")
			}
		})
	}
}
