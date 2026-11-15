package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestAuditDetectionActionWritesOperatorAuditLog(t *testing.T) {
	old := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = old })

	auditDetectionAction("run_module_denied", "uuid-1", "module=shell\n\x1b]0;x\x07")
	data, err := os.ReadFile(filepath.Join(live.EmpWorkSpace, operatorAuditFileName))
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
