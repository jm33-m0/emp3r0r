//go:build windows && amd64
// +build windows,amd64

package modules

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestParseCOFFArgs(t *testing.T) {
	env := []string{
		"PATH=/bin",
		"args=zhello i42 bdeadbeef",
		"IGNORED=value",
	}

	args, err := parseCOFFArgs(env)
	if err != nil {
		t.Fatalf("parseCOFFArgs returned error: %v", err)
	}

	want := []string{"zhello", "i42", "bdeadbeef"}
	if len(args) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %s want %s", i, args[i], want[i])
		}
	}
}

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
	if testing.Short() {
		t.Skip("skip BOF integration in short mode")
	}

	const url = "https://github.com/trustedsec/CS-Remote-OPs-BOF/raw/refs/heads/main/Remote/ProcessListHandles/ProcessListHandles.x64.o"
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

	pid := os.Getpid() // low-priv, alive
	inv := def.ResolvedInvocation{
		Coff: &def.ResolvedCoffInvocation{ // ProcessListHandles exports go(int pid)
			Export: "go",
			Args:   []def.ResolvedCoffArg{{WireType: "INT", Value: pid}},
		},
	}

	out, err := runCOFFModule(payload, inv)
	if err != nil {
		t.Fatalf("runCOFFModule failed: %v", err)
	}

	want := fmt.Sprintf("Listing handles for PID:%d", pid)
	if !strings.Contains(out, want) {
		t.Fatalf("unexpected BOF output: %q", out)
	}
}
