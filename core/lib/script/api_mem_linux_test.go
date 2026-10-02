//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
	"go.starlark.net/starlark"
)

// mockMemLibrarySource is a minimal valid ELF shared object; the test only
// needs memmod to map and unmap it.
const mockMemLibrarySource = `
#include <stdint.h>
__attribute__((visibility("default"))) int mem_marker(void) { return 1; }
`

func buildMockMemLibrary(t *testing.T) []byte {
	t.Helper()
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector enables checkptr, which conflicts with mapping arbitrary memory")
	}
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found in PATH")
	}

	var target string
	switch runtime.GOARCH {
	case "386":
		target = "x86-linux-gnu.2.17"
	case "amd64":
		target = "x86_64-linux-gnu.2.17"
	case "arm64":
		target = "aarch64-linux-gnu.2.17"
	default:
		t.Skipf("no zig target mapping for GOARCH %s", runtime.GOARCH)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "memlib.c")
	if err := os.WriteFile(src, []byte(mockMemLibrarySource), 0o600); err != nil {
		t.Fatalf("write mock source: %v", err)
	}
	out := filepath.Join(dir, "memlib.so")
	cmd := exec.Command("zig", "cc",
		"-target", target,
		"-shared", "-fPIC", "-fno-builtin",
		"-O2", "-g0",
		"-fno-sanitize=all",
		"-o", out, src,
	)
	cmd.Env = append(os.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-global-cache"),
		"ZIG_LOCAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-local-cache"),
	)
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zig cc failed: %v\n%s", err, buildOut)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read mock: %v", err)
	}
	return data
}

// TestReleaseRunModulesFreesMappedLibraries pins the guarantee that a script
// which maps a library through mem_load_library but never calls mem_free does
// not leave it mapped once the run ends.
func TestReleaseRunModulesFreesMappedLibraries(t *testing.T) {
	skipUnderRace(t)
	module, err := memmod.LoadLibrary(buildMockMemLibrary(t))
	if err != nil {
		t.Fatalf("LoadLibrary: %v", err)
	}

	thread := &starlark.Thread{}
	modulesForThread(thread).add(module.BaseAddr(), module)
	if module.BaseAddr() == 0 {
		t.Fatal("module base address is zero before release")
	}

	releaseRunModules(thread)
	if module.BaseAddr() != 0 {
		t.Fatalf("releaseRunModules left module mapped (base=%#x)", module.BaseAddr())
	}
}
