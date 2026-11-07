package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// TestDispatchModuleTracksJob covers the MCP run_module path: the caller gets
// the job ID back and that same ID must be the one the agent response is
// correlated with. A fresh random ID here leaves the MCP job forever pending
// and read_job_output returns "not found".
func TestDispatchModuleTracksJob(t *testing.T) {
	stubRemoteDownloads(t)
	origRoot, origSender, origActive := paths.WWWRoot, CmdSender, live.ActiveModule
	t.Cleanup(func() {
		paths.WWWRoot = origRoot
		CmdSender = origSender
		live.ActiveModule = origActive
	})

	paths.WWWRoot = t.TempDir()

	// Real manifests go through readModCondig so the COFF invocation is
	// synthesised from the parameters exactly as it is at runtime.
	writeModule := func(dir, manifest string) *def.ModuleConfig {
		t.Helper()
		cfg := filepath.Join(dir, "config.json")
		if err := os.WriteFile(cfg, []byte(manifest), 0o600); err != nil {
			t.Fatalf("write %s: %v", cfg, err)
		}
		config, err := readModCondig(cfg)
		if err != nil {
			t.Fatalf("read %s: %v", cfg, err)
		}
		return config
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "probe.x64.o"), []byte("payload"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	config := writeModule(dir, `{
		"name": "dispatch_probe",
		"platform": "Windows",
		"agent_config": {"files": ["probe.x64.o"], "type": "coff"},
		"parameters": [],
		"invocation": {"coff_export": "go"}
	}`)
	config.Path = dir
	def.Modules.Store(config.Name, config)
	registerModuleRunner(config.Name, moduleCustom)
	t.Cleanup(func() {
		def.Modules.Delete(config.Name)
		deleteModuleRunner(config.Name)
	})

	depDir := t.TempDir()
	for _, name := range []string{"COFFLoader.x64.dll", "COFFLoader.x86.dll"} {
		if err := os.WriteFile(filepath.Join(depDir, name), []byte("loader"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	dep := writeModule(depDir, `{
		"name": "coffloader",
		"platform": "Windows",
		"agent_config": {"files": ["COFFLoader.x64.dll", "COFFLoader.x86.dll"], "type": "dll"},
		"parameters": [],
		"invocation": {}
	}`)
	dep.Path = depDir
	def.Modules.Store(dep.Name, dep)
	t.Cleanup(func() { def.Modules.Delete(dep.Name) })

	var sentJobID, sentCmd string
	CmdSender = func(cmd, jobID, _ string) error {
		sentCmd, sentJobID = cmd, jobID
		return nil
	}

	target := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "target", GOOS: "windows", GOArch: "amd64"}
	jobID, err := DispatchModule(target, config.Name, nil)
	if err != nil {
		t.Fatalf("DispatchModule: %v", err)
	}
	if jobID == "" {
		t.Fatal("DispatchModule returned an empty job ID")
	}
	if sentJobID != jobID {
		t.Fatalf("command sent under job %q, DispatchModule reported %q", sentJobID, jobID)
	}
	if !strings.Contains(sentCmd, "--mod_name dispatch_probe") {
		t.Fatalf("command %q does not dispatch the module", sentCmd)
	}
	if live.ActiveModule != origActive {
		t.Fatalf("active module was not restored")
	}
}
