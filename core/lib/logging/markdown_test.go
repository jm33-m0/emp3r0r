//go:build !release

package logging

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRenderMarkdownRendersStructure(t *testing.T) {
	input := "# Report\n\n| check | result |\n| --- | --- |\n| loader | clean |\n\n- one\n- two\n"
	out := RenderMarkdown(input, 80)
	if strings.TrimSpace(out) == "" {
		t.Fatal("renderer produced no output")
	}
	if !strings.Contains(out, "Report") || !strings.Contains(out, "loader") || !strings.Contains(out, "two") {
		t.Fatalf("rendered output lost content:\n%s", out)
	}
	if out == input {
		t.Fatal("markdown was not rendered")
	}
}

func TestRenderMarkdownDoesNotExecuteHTML(t *testing.T) {
	out := RenderMarkdown("before\n\n<script>alert(1)</script>\n\nafter", 80)
	if strings.Contains(out, "<script>") {
		t.Fatalf("raw HTML survived rendering:\n%s", out)
	}
	if !strings.Contains(out, "before") || !strings.Contains(out, "after") {
		t.Fatalf("surrounding text lost:\n%s", out)
	}
}

func TestRenderMarkdownUsesConfiguredWidth(t *testing.T) {
	SetRenderWidth(40)
	defer SetRenderWidth(0)

	out := RenderMarkdown(strings.Repeat("word ", 80), 0)
	plain := string(stripANSICodes([]byte(out)))
	for _, line := range strings.Split(plain, "\n") {
		if utf8.RuneCountInString(line) > 40 {
			t.Fatalf("line exceeds configured width: %q", line)
		}
	}
}

func TestRenderMarkdownPlainDropsHeadingMarkers(t *testing.T) {
	out := RenderMarkdownPlain("# Title\n\n## Section\n\n- one", 80)
	if strings.Contains(out, "# Title") || strings.Contains(out, "## Section") {
		t.Fatalf("plain rendering kept heading markers:\n%s", out)
	}
	for _, want := range []string{"Title", "Section", "one"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plain rendering lost %q:\n%s", want, out)
		}
	}
}
