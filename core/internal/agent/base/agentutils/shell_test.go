package agentutils

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestDefaultShellResolution checks the real resolver against the host: the
// returned path must be a candidate and must exist, and repeated calls must
// return the same cached value.
func TestDefaultShellResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell resolution targets unix shells")
	}

	shell := DefaultShell()
	if shell == "" {
		t.Skip("no shell installed on this host")
	}
	found := false
	for _, candidate := range shellCandidates {
		if candidate == shell {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("DefaultShell() = %q, not one of %v", shell, shellCandidates)
	}
	if _, err := os.Stat(shell); err != nil {
		t.Fatalf("DefaultShell() = %q but it does not exist: %v", shell, err)
	}
	if again := DefaultShell(); again != shell {
		t.Fatalf("DefaultShell() not cached: first %q, second %q", shell, again)
	}
}

// TestExecuteShellRunsScript drives the real execution path end to end: on a
// host with a shell it verifies the script's output, and on a host without one
// it verifies the clear error instead of a failed exec.
func TestExecuteShellRunsScript(t *testing.T) {
	if DefaultShell() == "" {
		if _, err := ExecuteShell([]byte("echo hi"), nil, nil); err == nil {
			t.Fatal("ExecuteShell should fail when no shell is available")
		}
		return
	}

	const marker = "emp3r0r-shell-test-marker"
	out, err := ExecuteShell([]byte("echo "+marker), nil, nil)
	if err != nil {
		t.Fatalf("ExecuteShell: %v", err)
	}
	if !strings.Contains(out, marker) {
		t.Fatalf("ExecuteShell output = %q, want it to contain %q", out, marker)
	}
}
