package operator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestLoopLoggerTagsEveryClassLine(t *testing.T) {
	var out bytes.Buffer
	logger := newLoopLogger(&out)
	logger.logf(logging.ClassCycle, "cycle %d\nsecond line", 3)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q, want two", out.String())
	}
	for _, line := range lines {
		if !strings.Contains(line, "[cycle]") {
			t.Fatalf("line %q lost its class tag", line)
		}
	}
	if !strings.Contains(lines[0], "cycle 3") || !strings.Contains(lines[1], "second line") {
		t.Fatalf("unexpected lines: %q", lines)
	}
}

func TestLoopLoggerSanitizesProgressLines(t *testing.T) {
	var out bytes.Buffer
	logger := newLoopLogger(&out)
	logger.printf("sandbox said %s", "\x1b]0;pwn\x07\nvisible")
	if strings.Contains(out.String(), "\x1b]0;") || strings.Contains(out.String(), "\x07") {
		t.Fatalf("progress line kept a terminal escape: %q", out.String())
	}
	if !strings.Contains(out.String(), "visible") {
		t.Fatalf("progress line lost its text: %q", out.String())
	}
}
