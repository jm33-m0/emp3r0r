package script

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCIFSUploadModuleScript exercises the real cifs_upload / cifs_rm module
// (core/modules/cifs_upload/cifs_upload.star) through the engine. Only the
// safe, platform-independent paths are executed: command dispatch, argument
// validation, UNC parsing and payload-source resolution. The actual
// CreateFileW/WriteFile/DeleteFileW SMB operations need a live share +
// Windows and are intentionally not attempted here.
func TestCIFSUploadModuleScript(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to resolve caller path")
	}
	// core/lib/script -> core (repo root)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	modDir := filepath.Join(repoRoot, "modules", "cifs_upload")
	starPath := filepath.Join(modDir, "cifs_upload.star")
	src, err := os.ReadFile(starPath)
	if err != nil {
		t.Fatalf("read cifs_upload.star: %v", err)
	}

	// config.json must define both commands with correct literal argv
	// prefixes, reference the existing entry script and target Windows.
	cfgData, err := os.ReadFile(filepath.Join(modDir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var cfgs []struct {
		Name        string `json:"name"`
		AgentConfig struct {
			Exec  string   `json:"exec"`
			Files []string `json:"files"`
			Type  string   `json:"type"`
		} `json:"agent_config"`
		Platform   string `json:"platform"`
		Invocation struct {
			Argv []struct {
				Literal string `json:"literal"`
			} `json:"argv"`
		} `json:"invocation"`
	}
	if err := json.Unmarshal(cfgData, &cfgs); err != nil {
		t.Fatalf("config.json is not valid JSON: %v", err)
	}
	wantCmds := map[string]string{"cifs_upload": "upload", "cifs_rm": "delete"}
	for _, c := range cfgs {
		if c.AgentConfig.Type == "" {
			continue // not one of ours
		}
		wantCmd, want := wantCmds[c.Name]
		if !want {
			continue
		}
		if !strings.EqualFold(c.Platform, "windows") {
			t.Fatalf("module %s platform must be windows, got %q", c.Name, c.Platform)
		}
		if !strings.EqualFold(c.AgentConfig.Type, "starlark") {
			t.Fatalf("module %s type must be starlark, got %q", c.Name, c.AgentConfig.Type)
		}
		if c.AgentConfig.Exec != "cifs_upload.star" {
			t.Fatalf("module %s unexpected exec %q", c.Name, c.AgentConfig.Exec)
		}
		if len(c.Invocation.Argv) != 1 || c.Invocation.Argv[0].Literal != wantCmd {
			t.Fatalf("module %s: expected literal argv [%q], got %+v", c.Name, wantCmd, c.Invocation.Argv)
		}
		for _, f := range c.AgentConfig.Files {
			if _, err := os.Stat(filepath.Join(modDir, f)); err != nil {
				t.Fatalf("module %s file %s missing: %v", c.Name, f, err)
			}
		}
		delete(wantCmds, c.Name)
	}
	if len(wantCmds) != 0 {
		t.Fatalf("modules missing from config.json: %v", wantCmds)
	}

	run := func(args ...string) (string, error) {
		return Run(src, args, map[string]any{"module_files": []string{}}, 0)
	}

	// 1. No arguments at all → usage + clear failure.
	out, err := run()
	if err != nil {
		t.Fatalf("Run (no args): %v", err)
	}
	if !strings.Contains(out, "Fail: both src and dest are required") {
		t.Fatalf("expected src/dest failure, got: %q", out)
	}
	if !strings.Contains(out, "--src") || !strings.Contains(out, "--dest") || !strings.Contains(out, "--rmdir") {
		t.Fatalf("expected usage text, got: %q", out)
	}

	// 2. upload with missing src → same failure.
	out, err = run("upload", "", `\\DC01\ADMIN$\Temp\stage.exe`)
	if err != nil {
		t.Fatalf("Run upload (empty src): %v", err)
	}
	if !strings.Contains(out, "Fail: both src and dest are required") {
		t.Fatalf("expected src/dest failure, got: %q", out)
	}

	// 3. upload with a non-UNC dest → usage + clear failure.
	out, err = run("upload", "mem:///payload.exe", `C:\Windows\Temp\stage.exe`)
	if err != nil {
		t.Fatalf("Run upload (non-UNC dest): %v", err)
	}
	if !strings.Contains(out, "Fail: dest must be a full UNC path") {
		t.Fatalf("expected UNC failure, got: %q", out)
	}

	// 4. upload with valid UNC dest but missing memfs source → clean failure
	//    before any Win32 call (no share is ever touched).
	out, err = run("upload", "mem:///cifs_upload_missing_payload.bin", `\\DC01\ADMIN$\Temp\stage.exe`)
	if err != nil {
		t.Fatalf("Run upload (missing source): %v", err)
	}
	if !strings.Contains(out, "Fail: source") || !strings.Contains(out, "not found on this agent") {
		t.Fatalf("expected missing-source failure, got: %q", out)
	}
	if strings.Contains(out, "CreateFileW") {
		t.Fatalf("must not attempt a remote upload for a missing source, got: %q", out)
	}

	// 5. delete with no dest → clear failure (no Win32 call yet).
	out, err = run("delete")
	if err != nil {
		t.Fatalf("Run delete (no dest): %v", err)
	}
	if !strings.Contains(out, "Fail: dest (UNC path to the file or directory to remove) is required") {
		t.Fatalf("expected delete dest failure, got: %q", out)
	}

	// 6. delete with a non-UNC dest → clear failure.
	out, err = run("delete", `C:\Windows\Temp\stage.exe`)
	if err != nil {
		t.Fatalf("Run delete (non-UNC dest): %v", err)
	}
	if !strings.Contains(out, "Fail: dest must be a full UNC path") {
		t.Fatalf("expected delete UNC failure, got: %q", out)
	}

	// 7. unknown command word falls back to legacy upload behaviour.
	out, err = run("bogus")
	if err != nil {
		t.Fatalf("Run (bogus command): %v", err)
	}
	if !strings.Contains(out, "Fail: both src and dest are required") {
		t.Fatalf("expected legacy upload failure for unknown command, got: %q", out)
	}
}
