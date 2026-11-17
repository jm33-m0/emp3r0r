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
	logger.close()
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
	logger.close()
	if strings.Contains(out.String(), "\x1b]0;") || strings.Contains(out.String(), "\x07") {
		t.Fatalf("progress line kept a terminal escape: %q", out.String())
	}
	if !strings.Contains(out.String(), "visible") {
		t.Fatalf("progress line lost its text: %q", out.String())
	}
}

func TestLoopLoggerWritesPlainClassLines(t *testing.T) {
	var out bytes.Buffer
	logger := newLoopLogger(&out)
	logger.logf(logging.ClassCycle, "cycle %d", 3)
	logger.logf(logging.ClassModel, "## Heading\n\n- one")
	logger.close()
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("on-disk logger kept ANSI: %q", out.String())
	}
	for _, want := range []string{"[cycle]", "cycle 3", "[model]", "Heading", "one"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("plain log missing %q: %q", want, out.String())
		}
	}
}
