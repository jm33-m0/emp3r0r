//go:build windows && amd64
// +build windows,amd64

package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestRunCOFFModuleInvalidPayload(t *testing.T) {
	inv := def.ResolvedInvocation{
		Coff: &def.ResolvedCoffInvocation{
			Export: "Run",
			Args:   []def.ResolvedCoffArg{{WireType: "LPSTR", Value: "hello"}},
		},
	}

	// Invalid payload should bubble an error from loader; we just assert it tries to load.
	if _, err := runCOFFModule([]byte("not-a-coff"), inv); err == nil {
		t.Fatalf("expected error for invalid COFF payload")
	}
}

func TestRunCOFFModuleWithRealBOF(t *testing.T) {
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipped under race run (EMP3R0R_RACE_ON=1)")
	}

	payloadPath := filepath.Join(getModulesRoot(), "Remote-OPs/src/Remote/get_priv/get_priv.x64.o")
	if !util.IsExist(payloadPath) {
		makeDir := filepath.Join(getModulesRoot(), "Remote-OPs/src/Remote/get_priv")
		cmd := exec.Command("make", "-C", makeDir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to build %s with make -C %s: %v\nOutput: %s", payloadPath, makeDir, err, string(out))
		}
	}

	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("read BOF %s: %v", payloadPath, err)
	}

	inv := def.ResolvedInvocation{
		Coff: &def.ResolvedCoffInvocation{
			Export: "go",
			Args:   nil,
		},
	}

	out, err := runCOFFModule(payload, inv)
	if err != nil {
		t.Fatalf("runCOFFModule failed: %v", err)
	}

	if strings.TrimSpace(out) == "" {
		t.Fatalf("unexpected empty BOF output")
	}
}
