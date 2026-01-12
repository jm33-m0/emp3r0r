//go:build !windows

package modules

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestRunCOFFModuleNotSupported(t *testing.T) {
	_, err := runCOFFModule(nil, def.ResolvedInvocation{})
	if err == nil {
		t.Fatalf("expected not supported error on non-Windows")
	}
	if !strings.Contains(err.Error(), "only supported on Windows") {
		t.Fatalf("unexpected error: %v", err)
	}
}
