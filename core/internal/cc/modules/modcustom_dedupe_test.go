package modules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// writeTestModuleDir creates, under parent/mod, a module dir named `name`
// with a minimal config.json, and returns the search dir (parent/mod).
func writeTestModuleDir(t *testing.T, tmpDir, modParent, name, paramDefault string) string {
	t.Helper()
	searchDir := filepath.Join(tmpDir, modParent)
	modDir := filepath.Join(searchDir, name)
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", modDir, err)
	}
	cfg := `{
		"name": "` + name + `",
		"comment": "dedupe test module",
		"platform": "Linux",
		"agent_config": {"type": "go"},
		"parameters": [
			{"name": "who", "description": "who to greet", "default": "` + paramDefault + `", "type": "cstr", "required": false}
		]
	}`
	if err := os.WriteFile(filepath.Join(modDir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return searchDir
}

// TestInitModulesDedupe verifies that when the same module exists in more than
// one module dir (e.g. a built module copied into the workspace dir and then
// re-scanned), the first definition wins and the module is NOT re-registered
// from the second dir.
func TestInitModulesDedupe(t *testing.T) {
	tmpDir := t.TempDir()
	dirA := writeTestModuleDir(t, tmpDir, "modA", "dupmod", "from-system")
	dirB := writeTestModuleDir(t, tmpDir, "modB", "dupmod", "from-workspace-stale")

	// module dirs are scanned in order; workspace dir must exist for the copy
	// helper used by bof_common (only when bof_common exists — it does not here)
	oldDirs := live.ModuleDirs
	oldWWW := live.WWWRoot
	oldWS := live.EmpWorkSpace
	live.ModuleDirs = []string{dirA, dirB}
	live.WWWRoot = filepath.Join(tmpDir, "www")
	live.EmpWorkSpace = filepath.Join(tmpDir, "ws")
	if err := os.MkdirAll(live.WWWRoot, 0o700); err != nil {
		t.Fatalf("mkdir www: %v", err)
	}
	if err := os.MkdirAll(live.EmpWorkSpace, 0o700); err != nil {
		t.Fatalf("mkdir ws: %v", err)
	}
	defer func() {
		live.ModuleDirs = oldDirs
		live.WWWRoot = oldWWW
		live.EmpWorkSpace = oldWS
		def.Modules.Delete("dupmod")
		deleteModuleRunner("dupmod")
	}()

	InitModules()

	val, ok := def.Modules.Load("dupmod")
	if !ok {
		t.Fatal("dupmod was not registered")
	}
	mod, ok := val.(*def.ModuleConfig)
	if !ok {
		t.Fatalf("unexpected type %T", val)
	}
	// The canonical (first dir) definition must have won.
	opts := mod.Options
	if opts == nil {
		t.Fatal("module options missing")
	}
	who, ok := opts["who"]
	if !ok {
		t.Fatal("option 'who' missing")
	}
	if who.Val != "from-system" {
		t.Fatalf("expected first-dir default %q, got %q (module was overwritten by a later dir)", "from-system", who.Val)
	}
}
