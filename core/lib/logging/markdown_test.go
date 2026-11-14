//go:build !release

package logging

import (
	"strings"
	"testing"
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
