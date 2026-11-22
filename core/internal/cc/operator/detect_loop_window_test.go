package operator

import (
	"strings"
	"testing"
)

func TestDetectLoopWindowTitle(t *testing.T) {
	a := detectLoopWindowTitle("loop-20261122-190000")
	b := detectLoopWindowTitle("loop-20261122-190001")
	if a == b || !strings.HasPrefix(a, "detect loop-") {
		t.Fatalf("titles are not loop-specific: %q %q", a, b)
	}
	if got := detectLoopWindowTitle("loop-#{window_name}"); strings.Contains(got, "#") || strings.Contains(got, "{") {
		t.Fatalf("tmux format syntax survived: %q", got)
	}
}
