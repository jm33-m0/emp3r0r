package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestStripANSICodes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text passthrough", "sAMAccountName: Administrator", "sAMAccountName: Administrator"},
		{"SGR color around whole line", "\x1b[97m[*] Binding to dc\x1b[0m", "[*] Binding to dc"},
		{"SGR inside multi-value line", "\x1b[92;1mOK\x1b[0;22m", "OK"},
		{"result boundary must stay pure dashes", "\x1b[97m--------------------\x1b[0m", "--------------------"},
		{"CSI non-SGR", "\x1b[2Jclear\x1b[?25l", "clear"},
		{"lone ESC", "a\x1bb", "ab"},
		{"nested text after reset", "\x1b[36mtag\x1b[0m rest", "tag rest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(stripANSICodes([]byte(tc.in)))
			if got != tc.want {
				t.Fatalf("stripANSICodes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAnsiStripWriter(t *testing.T) {
	var buf bytes.Buffer
	w := ansiStripWriter{w: &buf}

	input := "\x1b[92;1m[+] Successfully bound\x1b[0;22m\n--------------------\n"
	n, err := w.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(input) { // original (uncleaned) length must be reported
		t.Fatalf("reported %d bytes, want %d", n, len(input))
	}
	if buf.String() != "[+] Successfully bound\n--------------------\n" {
		t.Fatalf("unexpected output: %q", buf.String())
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Fatalf("output still contains ESC: %q", buf.String())
	}
}
