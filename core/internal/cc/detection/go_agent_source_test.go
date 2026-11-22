package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsLoopExposesGoAgentSource(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "modules", "loader_windows")
	goAgentDir := filepath.Join(root, "go_agent")
	for _, dir := range []string{moduleDir, goAgentDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := &evolver{cfg: EvolveConfig{Module: "loader_windows", ModuleDir: moduleDir, Platform: platformWindows}}
	e.roots = e.sourceRoots()
	rootInfo, err := e.roots.pick("go_agent")
	if err != nil {
		t.Fatal(err)
	}
	if !rootInfo.Writable || rootInfo.Dir != goAgentDir {
		t.Fatalf("go_agent root = %+v", rootInfo)
	}
}
