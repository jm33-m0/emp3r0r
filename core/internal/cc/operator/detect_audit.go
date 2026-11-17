package operator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const operatorAuditFileName = "operator_audit.log"

// operatorAuditPath resolves the audit log next to the operator workspace.
// The detection loop runs in the console process, so it can fall back to the
// default workspace when a command starts before live.EmpWorkSpace is set.
func operatorAuditPath() string {
	root := strings.TrimSpace(live.EmpWorkSpace)
	if root == "" {
		if home, err := os.UserHomeDir(); err == nil {
			root = filepath.Join(home, ".emp3r0r")
		}
	}
	if root == "" {
		return ""
	}
	return filepath.Join(root, operatorAuditFileName)
}

// auditDetectionAction records one model-triggered C2 action, including a
// denial. The loop is driven by untrusted telemetry, so every agent lookup,
// module dispatch, agent forget, and denied attempt is attributable even
// though there is no interactive operator identity.
func auditDetectionAction(action, target, detail string) {
	auditDetectionActionAt(operatorAuditPath(), action, target, detail)
}

// auditDetectionActionAt writes one audit line at path. A single O_APPEND
// write keeps concurrent detection actions from interleaving without holding
// a lock across disk I/O.
func auditDetectionActionAt(path, action, target, detail string) {
	if path == "" {
		logging.Warningf("detection audit: no operator workspace for action %s", action)
		return
	}
	fields := []string{
		time.Now().Format(time.RFC3339),
		`operator="detect_loop"`,
		fmt.Sprintf("action=%q", sanitize.SanitizeOneLine(action)),
		fmt.Sprintf("target=%q", sanitize.SanitizeOneLine(target)),
	}
	if detail = strings.TrimSpace(detail); detail != "" {
		detail = sanitize.SanitizeOneLine(sanitize.RedactCommandSecrets(detail))
		fields = append(fields, fmt.Sprintf("detail=%q", detail))
	}
	line := strings.Join(fields, " ") + "\n"

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logging.Warningf("detection audit: open %s: %v", path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		logging.Warningf("detection audit: write: %v", err)
	}
}
