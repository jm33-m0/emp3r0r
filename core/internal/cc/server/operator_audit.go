package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// operatorAuditFileName is the server-side audit log, kept next to the
// operator config in the workspace.
const operatorAuditFileName = "operator_audit.log"

// auditMu serializes appends so concurrent operators never interleave a line.
var auditMu sync.Mutex

// operatorAuditPath returns the audit log path for the current workspace.
func operatorAuditPath() string {
	return filepath.Join(live.EmpWorkSpace, operatorAuditFileName)
}

// auditOperatorAction appends one timestamped line recording who did what on
// which target, including the operator's WireGuard IP and public key. It is
// best effort: a log failure is reported but never interrupts the action.
func auditOperatorAction(operatorID, action, target, detail string) {
	name, ip, pubkey := operatorID, operatorID, ""
	if cfg := operatorByIP(operatorID); cfg != nil {
		name, ip, pubkey = cfg.Name, cfg.IP, cfg.PublicKey
	}
	fields := []string{
		time.Now().Format(time.RFC3339),
		fmt.Sprintf("operator=%q", name),
		fmt.Sprintf("wg_ip=%q", ip),
		fmt.Sprintf("wg_pubkey=%q", pubkey),
		fmt.Sprintf("action=%q", action),
		fmt.Sprintf("target=%q", target),
	}
	if strings.TrimSpace(detail) != "" {
		fields = append(fields, fmt.Sprintf("detail=%q", detail))
	}
	line := strings.Join(fields, " ") + "\n"

	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.OpenFile(operatorAuditPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logging.Warningf("operator audit: open %s: %v", operatorAuditPath(), err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		logging.Warningf("operator audit: write: %v", err)
	}
}
