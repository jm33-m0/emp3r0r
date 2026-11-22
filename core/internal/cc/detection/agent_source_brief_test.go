package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentSourceBriefNamesCustomRoot(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "modules", "stager_linux")
	agentDir := filepath.Join(root, "custom-agent")
	for _, dir := range []string{moduleDir, agentDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := &evolver{cfg: EvolveConfig{
		Module: "stager_linux", ModuleDir: moduleDir,
		AgentSourceDir: agentDir, Platform: platformLinux,
	}}
	e.roots = e.sourceRoots()
	brief := e.agentSourceBrief()
	if !strings.Contains(brief, "custom-agent=") || !strings.Contains(brief, "(edit)") {
		t.Fatalf("agent source brief = %q", brief)
	}
}
