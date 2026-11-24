package detection

import (
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
