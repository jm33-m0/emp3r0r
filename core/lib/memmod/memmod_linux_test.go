//go:build linux && !android && (386 || amd64 || arm64)

package memmod

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// linuxFixtureSource is a self-contained shared library with a constructor and
// a couple of exports. It intentionally uses no TLS and no ifunc/IRELATIVE
// relocations so it exercises the loader without depending on the process
// dynamic loader.
const linuxFixtureSource = `
#include <stdint.h>

static uintptr_t ctor_bias;

__attribute__((constructor)) static void fixture_ctor(void) {
	ctor_bias = 0x1234;
}

__attribute__((visibility("default"))) uintptr_t FixtureAdd(uintptr_t a, uintptr_t b) {
	return a + b + ctor_bias;
}

__attribute__((visibility("default"))) uintptr_t FixtureZero(void) {
	return ctor_bias;
}
`

func skipUnderRaceLinux(t *testing.T) {
	t.Helper()
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector enables checkptr, which conflicts with mapping arbitrary memory")
	}
}

// buildLinuxFixture compiles linuxFixtureSource with zig cc into a shared
// object for the current architecture, pinned to the glibc 2.17 baseline that
// the shipped libraries use.
func buildLinuxFixture(t *testing.T) []byte {
	t.Helper()

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
	src := filepath.Join(dir, "fixture.c")
	if err := os.WriteFile(src, []byte(linuxFixtureSource), 0o600); err != nil {
		t.Fatalf("write fixture source: %v", err)
	}
	out := filepath.Join(dir, "fixture.so")

	cmd := exec.Command("zig", "cc",
		"-target", target,
		"-shared", "-fPIC",
		"-O2", "-g0",
		"-fno-sanitize=all",
		"-o", out, src,
	)
	cmd.Env = append(os.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+filepath.Join(os.TempDir(), "memmod-zig-global-cache"),
		"ZIG_LOCAL_CACHE_DIR="+filepath.Join(os.TempDir(), "memmod-zig-local-cache"),
	)
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zig cc failed: %v\n%s", err, buildOut)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestLoadLibraryELF(t *testing.T) {
	skipUnderRaceLinux(t)

	data := buildLinuxFixture(t)
	module, err := LoadLibrary(data)
	if err != nil {
		t.Fatalf("LoadLibrary: %v", err)
	}
	t.Cleanup(module.Free)

	if module.BaseAddr() == 0 {
		t.Fatal("BaseAddr returned 0")
	}

	addr, err := module.ProcAddressByName("FixtureAdd")
	if err != nil {
		t.Fatalf("ProcAddressByName(FixtureAdd): %v", err)
	}
	if addr < module.BaseAddr() {
		t.Fatalf("FixtureAdd address 0x%x is below module base 0x%x", addr, module.BaseAddr())
	}

	// The constructor must have run before the export is callable.
	got, err := module.CallExportWithArgs("FixtureAdd", 1, 2)
	if err != nil {
		t.Fatalf("CallExportWithArgs(FixtureAdd): %v", err)
	}
	if want := uintptr(1 + 2 + 0x1234); got != want {
		t.Fatalf("FixtureAdd(1, 2) = 0x%x, want 0x%x", got, want)
	}

	if err := module.CallExport("FixtureZero"); err != nil {
		t.Fatalf("CallExport(FixtureZero): %v", err)
	}
}

func TestLoadLibraryELFErrors(t *testing.T) {
	skipUnderRaceLinux(t)

	if _, err := LoadLibrary(nil); err == nil {
		t.Fatal("LoadLibrary(nil) succeeded, want error")
	}
	if _, err := LoadLibrary([]byte("not an ELF image")); err == nil {
		t.Fatal("LoadLibrary(garbage) succeeded, want error")
	}

	data := buildLinuxFixture(t)
	module, err := LoadLibrary(data)
	if err != nil {
		t.Fatalf("LoadLibrary: %v", err)
	}

	if _, err := module.ProcAddressByName("NoSuchExport"); err == nil {
		t.Fatal("ProcAddressByName(missing) succeeded, want error")
	}
	if _, err := module.CallExportWithArgs("FixtureAdd", 1, 2, 3, 4); err == nil || !strings.Contains(err.Error(), "maximum is 3") {
		t.Fatalf("CallExportWithArgs with too many args = %v, want argument-limit error", err)
	}
	if _, err := module.ProcAddressByOrdinal(1); err == nil {
		t.Fatal("ProcAddressByOrdinal succeeded on ELF, want error")
	}

	// Free must be idempotent.
	module.Free()
	module.Free()

	// The handle must be unusable after Free.
	if _, err := module.ProcAddressByName("FixtureAdd"); err == nil {
		t.Fatal("ProcAddressByName after Free succeeded, want error")
	}
}
