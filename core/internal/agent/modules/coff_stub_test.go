//go:build !windows

package modules

import (
	"strings"
	"testing"
)

func TestRunCOFFModuleNotSupported(t *testing.T) {
    _, err := runCOFFModule(nil, nil)
    if err == nil {
        t.Fatalf("expected not supported error on non-Windows")
    }
    if !strings.Contains(err.Error(), "only supported on Windows") {
        t.Fatalf("unexpected error: %v", err)
    }
}
