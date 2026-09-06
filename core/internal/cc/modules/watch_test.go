package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func newWatchTestRoot(t *testing.T) (searchDir, workspace string) {
	t.Helper()
	tmp := t.TempDir()
	searchDir = filepath.Join(tmp, "modules")
	workspace = filepath.Join(tmp, "ws")
	if err := os.MkdirAll(searchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return searchDir, workspace
}

func writeModule(t *testing.T, searchDir, name, body string) string {
	t.Helper()
	dir := filepath.Join(searchDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const simpleMod = `{
	"name": "%s",
	"comment": "hot reload test %s",
	"is_local": false,
	"fileless": true,
	"platform": "Linux",
	"agent_config": {"exec": "echo", "type": "elf", "files": []},
	"parameters": [
		{"name": "arg", "description": "arg for %s", "default": "hello", "type": "string"}
	],
	"invocation": {"argv": [{"literal": "echo"}]}
}`

func moduleBody(name, tag string) string {
	return fmt.Sprintf(simpleMod, name, tag, name)
}

func moduleLoaded(name string) bool {
	_, ok := def.Modules.Load(name)
	return ok
}

// setTestModuleDirs points the module globals at a throwaway tree and returns
// a restore func.
func setTestModuleDirs(t *testing.T, searchDir, workspace string) func() {
	t.Helper()
	origDirs := live.ModuleDirs
	origWS := live.EmpWorkSpace
	origWWW := live.WWWRoot
	live.ModuleDirs = []string{searchDir}
	live.EmpWorkSpace = workspace
	live.WWWRoot = filepath.Join(workspace, "www")
	return func() {
		live.ModuleDirs = origDirs
		live.EmpWorkSpace = origWS
		live.WWWRoot = origWWW
	}
}

func TestModuleWatchAddEditRemove(t *testing.T) {
	searchDir, workspace := newWatchTestRoot(t)
	defer setTestModuleDirs(t, searchDir, workspace)()

	for _, name := range []string{"watch_mod_a", "watch_mod_b", "watch_mod_a2"} {
		def.Modules.Delete(name)
		deleteModuleRunner(name)
	}

	writeModule(t, searchDir, "watch_mod_a", moduleBody("watch_mod_a", "v1"))
	InitModules()
	if !moduleLoaded("watch_mod_a") {
		t.Fatalf("watch_mod_a not loaded by InitModules")
	}

	StartModuleWatch()
	defer StopModuleWatch()

	waitFor := func(name string, want bool, timeout time.Duration) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if moduleLoaded(name) == want {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("module %s: want loaded=%v, timeout", name, want)
	}

	// add a new module dir -> loaded
	writeModule(t, searchDir, "watch_mod_b", moduleBody("watch_mod_b", "v1"))
	waitFor("watch_mod_b", true, 5*time.Second)

	// edit watch_mod_a config -> reloaded with the new comment
	writeModule(t, searchDir, "watch_mod_a", moduleBody("watch_mod_a", "v2"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if val, ok := def.Modules.Load("watch_mod_a"); ok &&
			val.(*def.ModuleConfig).Comment == "hot reload test v2" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if val, ok := def.Modules.Load("watch_mod_a"); !ok || val.(*def.ModuleConfig).Comment != "hot reload test v2" {
		t.Fatalf("watch_mod_a not reloaded with new config")
	}

	// remove watch_mod_b -> unloaded
	if err := os.RemoveAll(filepath.Join(searchDir, "watch_mod_b")); err != nil {
		t.Fatal(err)
	}
	waitFor("watch_mod_b", false, 5*time.Second)
	if !moduleLoaded("watch_mod_a") {
		t.Fatalf("watch_mod_a should still be loaded")
	}

	// rename (remove + create) watch_mod_a -> watch_mod_a2
	if err := os.Rename(filepath.Join(searchDir, "watch_mod_a"), filepath.Join(searchDir, "watch_mod_a2")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(searchDir, "watch_mod_a2", "config.json"),
		[]byte(moduleBody("watch_mod_a2", "v3")), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor("watch_mod_a2", true, 5*time.Second)
}

func TestModuleWatchBrokenConfig(t *testing.T) {
	searchDir, workspace := newWatchTestRoot(t)
	defer setTestModuleDirs(t, searchDir, workspace)()

	def.Modules.Delete("watch_broken")
	deleteModuleRunner("watch_broken")

	writeModule(t, searchDir, "watch_broken", moduleBody("watch_broken", "v1"))
	InitModules()
	if !moduleLoaded("watch_broken") {
		t.Fatal("watch_broken should be loaded initially")
	}

	StartModuleWatch()
	defer StopModuleWatch()

	// break the config: the module must be dropped from the registry
	dir := filepath.Join(searchDir, "watch_broken")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !moduleLoaded("watch_broken") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if moduleLoaded("watch_broken") {
		t.Fatal("watch_broken should have been dropped after config broke")
	}

	// fix the config: it must come back
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(moduleBody("watch_broken", "v2")), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if moduleLoaded("watch_broken") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !moduleLoaded("watch_broken") {
		t.Fatal("watch_broken should be reloaded after config fixed")
	}
}

func TestModuleWatchReconcileLogsOnlyChanges(t *testing.T) {
	// a reconcile over an unchanged tree must report no changes (and thus log
	// nothing) — that is what keeps the operator console quiet while idling.
	searchDir, _ := newWatchTestRoot(t)
	origDirs := live.ModuleDirs
	live.ModuleDirs = []string{searchDir}
	defer func() { live.ModuleDirs = origDirs }()
	writeModule(t, searchDir, "watch_silent", moduleBody("watch_silent", "v1"))

	w := &moduleWatch{state: make(map[string]string)}
	for _, dir := range moduleDirsOnDisk() {
		w.state[dir] = fingerprintConfig(dir)
	}
	if changes := w.reconcileOnce(); len(changes) != 0 {
		t.Fatalf("expected no changes on idle reconcile, got %v", changes)
	}

	// a non-config file change must not reload/log anything
	if err := os.WriteFile(filepath.Join(searchDir, "watch_silent", "payload.o"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changes := w.reconcileOnce(); len(changes) != 0 {
		t.Fatalf("expected no changes for non-config file, got %v", changes)
	}

	// editing the config reports exactly that one module as reloaded
	writeModule(t, searchDir, "watch_silent", moduleBody("watch_silent", "v2"))
	changes := w.reconcileOnce()
	expected := "reloaded: watch_silent (from " + filepath.Join(searchDir, "watch_silent") + ")"
	if len(changes) != 1 || changes[0] != expected {
		t.Fatalf("expected %q, got %v", expected, changes)
	}

	// a third pass is silent again (state absorbed the change)
	if changes := w.reconcileOnce(); len(changes) != 0 {
		t.Fatalf("expected no changes after absorbed edit, got %v", changes)
	}

	// a brand-new module dir is reported as "loaded"
	writeModule(t, searchDir, "watch_new", moduleBody("watch_new", "v1"))
	changes = w.reconcileOnce()
	if len(changes) != 1 || !strings.HasPrefix(changes[0], "loaded: watch_new ") {
		t.Fatalf("expected one 'loaded' change for the new module, got %v", changes)
	}

	// removing the module dir is reported as "removed"
	if err := os.RemoveAll(filepath.Join(searchDir, "watch_new")); err != nil {
		t.Fatal(err)
	}
	changes = w.reconcileOnce()
	if len(changes) != 1 || !strings.HasPrefix(changes[0], "removed: watch_new") {
		t.Fatalf("expected one 'removed' change, got %v", changes)
	}
}

func TestModuleWatchLocalModuleReloadNoLoop(t *testing.T) {
	// A local (is_local) module lives in a "prefix" search dir and is copied
	// into the workspace when loaded. Editing its prefix config must reload it
	// exactly once — the workspace copy we create ourselves must not be
	// reported as another change (no reload loop, no log spam).
	searchDir, workspace := newWatchTestRoot(t)
	defer setTestModuleDirs(t, searchDir, workspace)()

	def.Modules.Delete("watch_local")
	deleteModuleRunner("watch_local")

	body := `{
		"name": "watch_local",
		"comment": "local hot reload test %s",
		"is_local": true,
		"fileless": false,
		"platform": "Linux",
		"agent_config": {"exec": "x.sh", "type": "bash", "files": ["x.sh"]},
		"parameters": [],
		"invocation": {"argv": [{"literal": "x.sh"}]}
	}`
	dir := writeModule(t, searchDir, "watch_local", fmt.Sprintf(body, "v1"))
	if err := os.WriteFile(filepath.Join(dir, "x.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	InitModules()

	val, ok := def.Modules.Load("watch_local")
	if !ok || val.(*def.ModuleConfig).Comment != "local hot reload test v1" {
		t.Fatalf("local module not loaded: ok=%v", ok)
	}
	// Path must point at the workspace copy
	wsPath := filepath.Join(workspace, "modules", "watch_local")
	if val.(*def.ModuleConfig).Path != wsPath {
		t.Fatalf("local module Path = %q, want workspace copy %q", val.(*def.ModuleConfig).Path, wsPath)
	}

	StartModuleWatch()
	defer StopModuleWatch()

	// edit the prefix config -> reload (and re-copy) exactly once
	writeModule(t, searchDir, "watch_local", fmt.Sprintf(body, "v2"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if val, ok := def.Modules.Load("watch_local"); ok &&
			val.(*def.ModuleConfig).Comment == "local hot reload test v2" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if val, ok := def.Modules.Load("watch_local"); !ok || val.(*def.ModuleConfig).Comment != "local hot reload test v2" {
		t.Fatalf("local module not reloaded after prefix config edit")
	}
	// workspace copy config must reflect the edit
	data, err := os.ReadFile(filepath.Join(wsPath, "config.json"))
	if err != nil || !strings.Contains(string(data), "local hot reload test v2") {
		t.Fatalf("workspace copy not refreshed: %v", err)
	}

	// wait a beat: a reload loop would keep flipping the comment back / spamming
	time.Sleep(700 * time.Millisecond)
	if val, ok := def.Modules.Load("watch_local"); !ok || val.(*def.ModuleConfig).Comment != "local hot reload test v2" {
		t.Fatalf("module regressed after quiet period: %+v", val)
	}
}

// TestModuleWatchIntegrationRepoModules runs the watcher against the repo's
// own real module tree (many configs, subdirs, shared bof_common dir, etc.)
// with a temp workspace, verifying that an idle watch changes nothing and an
// edit to one module does not disturb the others.
func TestModuleWatchIntegrationRepoModules(t *testing.T) {
	modulesRoot, err := repoModulesRoot()
	if err != nil {
		t.Fatal(err)
	}

	ws := t.TempDir()
	origDirs := live.ModuleDirs
	origWS := live.EmpWorkSpace
	origWWW := live.WWWRoot
	live.ModuleDirs = []string{modulesRoot}
	live.EmpWorkSpace = ws
	live.WWWRoot = filepath.Join(ws, "www")
	defer func() {
		live.ModuleDirs = origDirs
		live.EmpWorkSpace = origWS
		live.WWWRoot = origWWW
	}()

	// snapshot and clear the registry so the count below only reflects our
	// scan of modulesRoot
	backup := make(map[string]any)
	def.Modules.Range(func(k, v any) bool {
		backup[k.(string)] = v
		def.Modules.Delete(k)
		return true
	})
	defer func() {
		def.Modules.Range(func(k, _ any) bool {
			def.Modules.Delete(k)
			return true
		})
		for k, v := range backup {
			def.Modules.Store(k, v)
		}
	}()

	InitModules()
	before := countModules()
	if before == 0 {
		t.Fatalf("no modules loaded from %s", modulesRoot)
	}

	StartModuleWatch()
	defer StopModuleWatch()

	// idle for >1 periodic tick: nothing may change
	time.Sleep(1100 * time.Millisecond)
	if after := countModules(); after != before {
		t.Fatalf("module count changed while idle: %d -> %d", before, after)
	}

	// touch one module's config (append a newline so the fingerprint changes)
	// and make sure the watcher stays healthy and the count stays stable
	cfgPath := filepath.Join(modulesRoot, "hello_linux", "config.json")
	origData, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", cfgPath, err)
	}
	if err := os.WriteFile(cfgPath, append(origData, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.WriteFile(cfgPath, origData, 0o644) }()

	time.Sleep(1200 * time.Millisecond)
	if after := countModules(); after != before {
		t.Fatalf("module count changed after config touch: %d -> %d", before, after)
	}
}

func repoModulesRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "modules"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func countModules() int {
	n := 0
	def.Modules.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
