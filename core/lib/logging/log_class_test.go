//go:build !release

package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestSafeTerminalTextKeepsSGRAndDropsControlSequences(t *testing.T) {
	in := "\x1b[31mred\x1b[0m \x1b]0;title\x07text \x1b[2Jcleared\x1b[1;32mok"
	out := safeTerminalText(in)
	if !strings.Contains(out, "\x1b[31mred\x1b[0m") {
		t.Fatalf("SGR was stripped: %q", out)
	}
	for _, bad := range []string{"\x1b]0;", "title", "\x1b[2J", "\x07"} {
		if strings.Contains(out, bad) {
			t.Fatalf("output still contains %q: %q", bad, out)
		}
	}
	if !strings.Contains(out, "text cleared") || !strings.Contains(out, "\x1b[1;32mok") {
		t.Fatalf("text or style lost: %q", out)
	}
}

func TestClassfSanitizesFormatInjection(t *testing.T) {
	old := logger
	var buf bytes.Buffer
	logger = &Logger{writer: &buf}
	defer func() { logger = old }()

	Classf(ClassLine, "\x1b]0;evil\x07%s", "visible")
	out := buf.String()
	if strings.Contains(out, "\x1b]0;") || strings.Contains(out, "\x07") {
		t.Fatalf("Classf wrote an OSC sequence: %q", out)
	}
	if !strings.Contains(out, "visible") {
		t.Fatalf("Classf lost the message: %q", out)
	}
}
