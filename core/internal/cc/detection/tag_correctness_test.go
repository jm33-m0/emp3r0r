package detection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDesignKeyIncludesAgentTags(t *testing.T) {
	derived := designKey("hash", nil, nil, "donut", "windows_executable", nil)
	slim := designKey("hash", nil, nil, "donut", "windows_executable", []string{})
	mesh := designKey("hash", nil, nil, "donut", "windows_executable", []string{"with_mesh"})
	if derived == slim {
		t.Fatal("nil and empty tag sets produce the same design key")
	}
	if derived == mesh || slim == mesh {
		t.Fatal("a tag change does not change the design key")
	}
}

func TestRestoreAgentSelection(t *testing.T) {
	e := &evolver{cfg: EvolveConfig{AgentType: "windows_dll", AgentTags: []string{"with_mesh"}}}
	empty := []string{}
	e.restoreAgentSelection(&cycleSummary{AgentType: "windows_executable", AgentTags: &empty})
	if e.cfg.AgentType != "windows_executable" || e.cfg.AgentTags == nil || len(e.cfg.AgentTags) != 0 {
		t.Fatalf("restored selection = %q %v", e.cfg.AgentType, e.cfg.AgentTags)
	}
	e.restoreAgentSelection(&cycleSummary{})
	if e.cfg.AgentType != "windows_executable" || len(e.cfg.AgentTags) != 0 {
		t.Fatalf("older summary changed selection: %q %v", e.cfg.AgentType, e.cfg.AgentTags)
	}
	nilTags := []string(nil)
	e.restoreAgentSelection(&cycleSummary{AgentTags: &nilTags})
	if e.cfg.AgentTags != nil {
		t.Fatalf("derived tag set restored as %v", e.cfg.AgentTags)
	}
}

func TestTagOnlyChangePassesCyclePreconditions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.go")
	if err := os.WriteFile(path, []byte("package agent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := newSourceRoots("loader_windows", sourceRoot{Name: "loader_windows", Dir: dir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: dir,
			AgentType: "windows_executable", AgentTags: []string{"with_quic"},
		},
		roots: roots,
	}
	sourceHash := e.computeSourceTreeHash()
	lastTags := []string{"with_mesh"}
	summary := cycleSummary{
		SourceTreeHash: sourceHash, BuildOptions: e.buildOptionsSnapshot(),
		ProducerOptions: e.activeProducerOptions(), Producer: e.activeProducer, AgentType: "windows_executable",
		AgentTags: &lastTags,
	}
	summary.DesignKey = designKey(sourceHash, summary.BuildOptions, summary.ProducerOptions, summary.Producer, summary.AgentType, lastTags)
	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	e.last = &Cycle{Iteration: 1, Summary: string(body)}
	if err := e.cyclePreconditions("other"); err != nil {
		t.Fatalf("tag-only change was rejected: %v", err)
	}
}
