//go:build linux && !android && (386 || amd64 || arm64)

package memdeps

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

// mockDepSource is a minimal valid ELF shared object; the tests only need
// memmod to map and unmap it, not to call anything in it.
const mockDepSource = `
#include <stdint.h>
__attribute__((visibility("default"))) int dep_marker(void) { return 42; }
`

func buildMockDep(t *testing.T) []byte {
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
	src := filepath.Join(dir, "dep.c")
	if err := os.WriteFile(src, []byte(mockDepSource), 0o600); err != nil {
		t.Fatalf("write mock source: %v", err)
	}
	out := filepath.Join(dir, "dep.so")
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

// TestRunMapsAndReleases pins the core invariant of this package: the mapping
// exists inside the callback and is gone once Run returns.
func TestRunMapsAndReleases(t *testing.T) {
	data := buildMockDep(t)
	var captured *memmod.Module
	var base uintptr
	if err := Run(data, func(module *memmod.Module) error {
		captured = module
		base = module.BaseAddr()
		return nil
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if base == 0 {
		t.Fatal("module base address was zero inside Run")
	}
	if captured.BaseAddr() != 0 {
		t.Fatalf("module still mapped after Run returned (base=%#x)", captured.BaseAddr())
	}
}

// TestRunReleasesOnCallbackError ensures a failed callback still releases the
// mapping.
func TestRunReleasesOnCallbackError(t *testing.T) {
	data := buildMockDep(t)
	boom := errors.New("boom")
	var captured *memmod.Module
	err := Run(data, func(module *memmod.Module) error {
		captured = module
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Run error = %v, want %v", err, boom)
	}
	if captured.BaseAddr() != 0 {
		t.Fatal("module still mapped after Run returned an error")
	}
}

func TestRunRejectsEmptyImage(t *testing.T) {
	called := false
	if err := Run(nil, func(*memmod.Module) error { called = true; return nil }); err == nil {
		t.Fatal("Run accepted an empty image")
	}
	if called {
		t.Fatal("callback ran for an empty image")
	}
}

func TestUseResolvesAndReleases(t *testing.T) {
	data := buildMockDep(t)
	SetResolver(func(name string) ([]byte, error) {
		if name != "dep" {
			t.Fatalf("resolver got name %q, want %q", name, "dep")
		}
		return data, nil
	})
	t.Cleanup(func() { SetResolver(nil) })

	var captured *memmod.Module
	if err := Use("dep", func(module *memmod.Module) error {
		captured = module
		return nil
	}); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if captured.BaseAddr() != 0 {
		t.Fatalf("module still mapped after Use returned (base=%#x)", captured.BaseAddr())
	}
}

func TestUseRequiresResolver(t *testing.T) {
	SetResolver(nil)
	if err := Use("dep", func(*memmod.Module) error { return nil }); err == nil {
		t.Fatal("Use succeeded without a resolver")
	}
	if err := Use("", func(*memmod.Module) error { return nil }); err == nil {
		t.Fatal("Use accepted an empty dependency name")
	}

	wantErr := errors.New("fetch failed")
	SetResolver(func(string) ([]byte, error) { return nil, wantErr })
	t.Cleanup(func() { SetResolver(nil) })
	if err := Use("dep", func(*memmod.Module) error { return nil }); !errors.Is(err, wantErr) {
		t.Fatalf("Use error = %v, want %v", err, wantErr)
	}
}
