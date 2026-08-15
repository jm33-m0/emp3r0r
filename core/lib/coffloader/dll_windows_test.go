//go:build windows && amd64

package coffloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWindowsCOFFViaDLL(t *testing.T) {
	modulesRoot := getModulesRoot()
	dllPath := filepath.Join(modulesRoot, "coffloader", "COFFLoader.x64.dll")
	dllData, err := os.ReadFile(dllPath)
	if err != nil {
		t.Skipf("skipping: COFFLoader DLL not found: %v", err)
	}

	bofPath := filepath.Join(modulesRoot, "Remote-OPs", "src", "Remote", "get_priv", "get_priv.x64.o")
	payload, err := os.ReadFile(bofPath)
	if err != nil {
		t.Skipf("skipping: BOF payload not found: %v", err)
	}

	args := []CoffArg{{WireType: "z", Value: "SeShutdownPrivilege"}}
	out, err := RunWindowsCOFFViaDLL(dllData, payload, "go", args, 0)
	if err != nil {
		t.Fatalf("RunWindowsCOFFViaDLL failed: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("expected non-empty BOF output, got %q", out)
	}
	t.Logf("BOF output:\n%s", out)
}
