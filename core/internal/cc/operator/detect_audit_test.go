package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDetectionActionWritesOperatorAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), operatorAuditFileName)
	auditDetectionActionAt(path, "run_module_denied", "uuid-1", "module=shell\n\x1b]0;x\x07")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	for _, want := range []string{`operator="detect_loop"`, `action="run_module_denied"`, `target="uuid-1"`, "module=shell"} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line missing %q: %q", want, line)
		}
	}
	if strings.Contains(line, "\x1b") || strings.Contains(line, "\x07") {
		t.Fatalf("audit line kept a terminal escape: %q", line)
	}
}
