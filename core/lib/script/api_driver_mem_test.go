package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// skipUnderRace skips tests that map arbitrary non-Go memory when the race
// detector is enabled (CI sets EMP3R0R_RACE_ON=1 for the race step), the
// same gate the memmod package itself uses.
func skipUnderRace(t *testing.T) {
	t.Helper()
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector is enabled")
	}
}

func TestDriverAPIs(t *testing.T) {
	// driver_is_loaded never errors and must be false for a made-up service.
	out, err := Run([]byte(`
def main(*args):
    if driver_is_loaded("emp3r0r_definitely_not_a_driver"):
        return "Fail: phantom driver reported as loaded"
    return "OK"
`), nil, nil, 0)
	if err != nil {
		t.Fatalf("driver_is_loaded script failed: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK from driver_is_loaded script, got: %q", out)
	}

	// driver_is_signed on a missing file must surface the underlying error.
	missing := filepath.Join(t.TempDir(), "missing.sys")
	_, err = Run([]byte(`
def main(*args):
    driver_is_signed("`+strings.ReplaceAll(missing, `\`, `\\`)+`")
    return "Fail: driver_is_signed succeeded on missing file"
`), nil, nil, 0)
	if err == nil {
		t.Errorf("expected error from driver_is_signed on missing file, but got none")
	} else if !strings.Contains(err.Error(), "driver_is_signed") {
		t.Errorf("expected driver_is_signed error, got: %v", err)
	}

	// driver_load with an empty path must fail argument validation.
	_, err = Run([]byte(`
def main(*args):
    driver_load("", "")
    return "Fail: driver_load accepted empty args"
`), nil, nil, 0)
	if err == nil {
		t.Errorf("expected error from driver_load with empty args, but got none")
	}

	if runtime.GOOS != "windows" {
		// The driver package's !windows stubs must surface as an error.
		_, err := Run([]byte(`
def main(*args):
    driver_load("C:\\drivers\\test.sys", "TestDriver")
    return "Fail: driver_load succeeded on non-Windows"
`), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when calling driver_load on non-Windows, but got none")
		} else if !strings.Contains(err.Error(), "not supported") {
			t.Errorf("expected 'not supported' error on non-Windows, got: %v", err)
		}
	}
}

func TestMemAPIs(t *testing.T) {
	if runtime.GOOS != "windows" {
		// mem_* must fail with a descriptive error instead of being undefined.
		_, err := Run([]byte(`
def main(*args):
    mem_load_library("deadbeef")
    return "Fail: mem_load_library succeeded on non-Windows"
`), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when calling mem_load_library on non-Windows, but got none")
		} else if !strings.Contains(err.Error(), "mem_load_library is only supported on Windows") {
			t.Errorf("expected 'only supported on Windows' error, got: %v", err)
		}
		return
	}

	skipUnderRace(t)

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = os.Getenv("WINDIR")
	}
	if systemRoot == "" {
		t.Fatal("SystemRoot/WINDIR environment variable not set")
	}
	ntdll, err := os.ReadFile(filepath.Join(systemRoot, "System32", "ntdll.dll"))
	if err != nil {
		t.Fatalf("failed to read ntdll.dll: %v", err)
	}

	// Embed the DLL bytes into the script via custom globals (the script
	// engine converts []byte to starlark.Bytes).
	out, err := Run([]byte(`
def main(*args):
    # mem_load is an alias for mem_load_library
    mod = mem_load(ntdll_bytes)
    if mod == 0:
        return "Fail: mem_load returned 0"
    if mem_base_addr(mod) != mod:
        return "Fail: mem_base_addr mismatch"

    # Resolve an export and verify the address is inside the module.
    addr = mem_proc_address(mod, "NtQuerySystemInformation")
    if addr == 0:
        return "Fail: NtQuerySystemInformation not found"
    if addr < mod:
        return "Fail: resolved address below module base"

    mem_free(mod)
    return "OK"
`), nil, map[string]any{"ntdll_bytes": starlark.Bytes(ntdll)}, 0)
	if err != nil {
		t.Fatalf("mem script failed: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK from mem script, got: %q", out)
	}

	// Freeing an unregistered handle must error.
	_, err = Run([]byte(`
def main(*args):
    mem_free(0x1234)
    return "Fail: mem_free on unknown handle succeeded"
`), nil, nil, 0)
	if err == nil {
		t.Errorf("expected error from mem_free on unknown handle, but got none")
	} else if !strings.Contains(err.Error(), "unknown module handle") {
		t.Errorf("expected 'unknown module handle' error, got: %v", err)
	}

	// Loading garbage must return an error.
	_, err = Run([]byte(`
def main(*args):
    mem_load_library("this is not a PE image")
    return "Fail: mem_load_library accepted garbage"
`), nil, nil, 0)
	if err == nil {
		t.Errorf("expected error when loading garbage, but got none")
	} else if !strings.Contains(err.Error(), "mem_load_library") {
		t.Errorf("expected mem_load_library error, got: %v", err)
	}
}
