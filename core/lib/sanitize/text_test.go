package sanitize

import (
	"strings"
	"testing"
)

// sanitize_test.go — terminal-injection defense tests.
//
// Sanitize* is the last line of defense between agent-controlled strings and
// the operator console/log file. The tests here deliberately try to smuggle
// control characters, ANSI/OSC escape sequences (including the classic
// `\x1b]0;<cmd>\x07` terminal-title injection used to spoof prompts) and
// invalid UTF-8 past the filters.

func TestSanitizeText_StripsTerminalEscapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is preserved", "hello world 123", "hello world 123"},
		{"SGR color", "\x1b[31mred\x1b[0m", "red"},
		{"SGR with params", "\x1b[38;5;196mbold\x1b[39m", "bold"},
		{"OSC title injection", "before\x1b]0;id;cat /etc/shadow\x07after", "beforeafter"},
		{"BEL char", "beep\x07ing", "beeping"},
		{"control chars dropped", "a\x00b\x01c\x1fd", "abcd"},
		{"newlines preserved (multi-line output)", "line1\nline2\ttabbed", "line1\nline2\ttabbed"},
		{"lone ESC dropped", "a\x1b z", "a z"},
		{"ESC+letter defanged (ESC b tabset)", "a\x1bb", "ab"},
		{"curses move-home", "x\x1b[H y", "x y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeText(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeText(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsRune(got, '\x1b') {
				t.Fatalf("output still contains ESC: %q", got)
			}
		})
	}
}

func TestSanitizeOneLine_CollapsesAllWhitespace(t *testing.T) {
	in := "multi\nline\twith   \r\n control\v chars"
	got := SanitizeOneLine(in)
	if got != "multi line with control chars" {
		t.Fatalf("SanitizeOneLine(%q) = %q", in, got)
	}
	if strings.ContainsAny(got, "\n\t\r\x00\x1b") {
		t.Fatalf("SanitizeOneLine left dangerous bytes: %q", got)
	}
}

func TestSanitizeText_InvalidUTF8(t *testing.T) {
	// 0xff is not valid UTF-8; it must be dropped, not panic or pass through.
	got := SanitizeText("a\xff\xfeb")
	if got != "ab" {
		t.Fatalf("SanitizeText with invalid UTF-8 = %q, want \"ab\"", got)
	}

	// Embedded binary beyond the printable range must be removed.
	bin := []byte{0x01, 0x02, 0x03, 0x04}
	got = SanitizeText(string(bin))
	if got != "" {
		t.Fatalf("SanitizeText(binary) = %q, want empty", got)
	}
}

func TestSanitizeText_NoOutputAmplification(t *testing.T) {
	// A hostile agent must not be able to blow up the operator console by
	// sending huge binary/hex content: StripANSI (legacy) appends a hex dump,
	// SanitizeText must NOT (it is used for rendering untrusted agent output).
	big := strings.Repeat("\x00\x01\x02", 10000)
	if got := SanitizeText(big); len(got) != 0 {
		t.Fatalf("SanitizeText should drop all binary without hex dump, got %d bytes", len(got))
	}
}

func TestStripANSI_HexDumpAnchored(t *testing.T) {
	got := StripANSI("\x01\x02\x03 [Binary data stripped]:")
	// must contain the anchor so the stripped dump is identifiable
	if !strings.Contains(got, "[Binary data stripped]:") {
		t.Fatalf("StripANSI output missing anchor: %q", got)
	}
	if !strings.Contains(got, "00000000") {
		t.Fatalf("StripANSI output missing hex offset: %q", got)
	}
}

func TestSanitizeText_UnicodeKept(t *testing.T) {
	in := "你好 🌍 OK"
	if got := SanitizeText(in); got != in {
		t.Fatalf("SanitizeText mangled unicode: %q", got)
	}
}
