package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLoopSummaryPrefersSummaryFile(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "loop.md")
	if err := os.WriteFile(reportPath, []byte("# Full\n\n## Outcome\n\nlong\n\n## Cycles\n\n| # |\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "loop-summary.md"), []byte("# Summary\n\nshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, source := readLoopSummary(reportPath)
	if got != "# Summary\n\nshort\n" || source != filepath.Join(dir, "loop-summary.md") {
		t.Fatalf("unexpected summary: %q from %q", got, source)
	}
}

func TestReadLoopSummaryFallsBackBeforeCycleTable(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "loop.md")
	body := "# Full\n\n## Outcome\n\nlong\n\n## Cycles\n\n| # |\n"
	if err := os.WriteFile(reportPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, source := readLoopSummary(reportPath)
	if source != reportPath {
		t.Fatalf("fallback source = %q, want %q", source, reportPath)
	}
	if strings.Contains(got, "## Cycles") || !strings.Contains(got, "## Outcome") {
		t.Fatalf("fallback kept the cycle table or lost the outcome:\n%s", got)
	}
}
