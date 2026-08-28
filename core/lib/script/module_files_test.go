package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// TestMultiFileModuleTransparency verifies the multi-file module flow from
// the script's point of view: companion files cached in memfs by the module
// loader are readable via read_file(), and the module_files global exposes
// their mem:/// paths.
func TestMultiFileModuleTransparency(t *testing.T) {
	const memPath = "mem:///multifilemod/data.txt"
	content := "emp3r0r multi-file module companion data\n"

	if err := util.WriteFileAgent(memPath, []byte(content), 0o600); err != nil {
		t.Fatalf("seed memfs: %v", err)
	}
	defer util.RemoveFileAgent(memPath)

	src := `
def main(*args):
    if len(module_files) != 1:
        return "Fail: expected 1 companion file, got %d" % len(module_files)
    if module_files[0] != "mem:///multifilemod/data.txt":
        return "Fail: unexpected path %s" % module_files[0]
    data = read_file(module_files[0])
    if "emp3r0r" not in data:
        return "Fail: companion content not readable"
    return "OK"
`
	out, err := Run([]byte(src), nil, map[string]any{
		"module_files": []string{memPath},
	}, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected OK, got: %q", out)
	}
}

// TestKkyumModuleScript runs the real multi-file module script
// (core/modules/kkyum/kkyum.star) through the engine. Only the safe paths
// are exercised: status/unload on a non-existent service and argument
// validation. The actual driver load needs a signed image + admin rights and
// is intentionally not attempted here.
func TestKkyumModuleScript(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to resolve caller path")
	}
	// core/lib/script -> core (repo root)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	starPath := filepath.Join(repoRoot, "modules", "kkyum", "kkyum.star")
	src, err := os.ReadFile(starPath)
	if err != nil {
		t.Fatalf("read kkyum.star: %v", err)
	}

	// status on a non-existent driver service must report "not loaded"
	out, err := Run(src, []string{"status", "kkyum_test_nonexistent"}, map[string]any{"module_files": []string{}}, 0)
	if err != nil {
		t.Fatalf("Run status: %v", err)
	}
	if !strings.Contains(out, "is not loaded") {
		t.Fatalf("expected 'not loaded' status, got: %q", out)
	}

	// unload on a non-existent service must be a no-op
	out, err = Run(src, []string{"unload", "kkyum_test_nonexistent"}, map[string]any{"module_files": []string{}}, 0)
	if err != nil {
		t.Fatalf("Run unload: %v", err)
	}
	if !strings.Contains(out, "is not loaded") {
		t.Fatalf("expected 'not loaded' unload, got: %q", out)
	}

	// load without companion files must fail cleanly
	out, err = Run(src, []string{"load", "kkyum_test_nonexistent"}, map[string]any{"module_files": []string{}}, 0)
	if err != nil {
		t.Fatalf("Run load(no files): %v", err)
	}
	if !strings.Contains(out, "no companion files uploaded") {
		t.Fatalf("expected companion-file failure, got: %q", out)
	}

	// unknown action
	out, err = Run(src, []string{"bogus"}, map[string]any{"module_files": []string{}}, 0)
	if err != nil {
		t.Fatalf("Run bogus action: %v", err)
	}
	if !strings.Contains(out, "unknown action") {
		t.Fatalf("expected unknown-action failure, got: %q", out)
	}
}
