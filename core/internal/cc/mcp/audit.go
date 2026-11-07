package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

// AuditRecord is one screened action. It deliberately stores a hash of file
// content rather than the content itself, and redacts secret-looking flags.
type AuditRecord struct {
	Time     string            `json:"time"`
	Operator string            `json:"operator,omitempty"`
	Tool     string            `json:"tool"`
	Target   string            `json:"target,omitempty"`
	Module   string            `json:"module,omitempty"`
	Flags    map[string]string `json:"flags,omitempty"`
	Command  string            `json:"command,omitempty"`
	Path     string            `json:"path,omitempty"`
	Bytes    int               `json:"bytes,omitempty"`
	SHA256   string            `json:"sha256,omitempty"`
	Rules    []string          `json:"rules,omitempty"`
	Noise    string            `json:"noise,omitempty"`
	Phase    string            `json:"phase,omitempty"`
	Allowed  bool              `json:"allowed"`
	Reason   string            `json:"reason,omitempty"`
	JobID    string            `json:"job_id,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// Audit appends JSON lines to a 0600 file. A nil Audit is a no-op so tests can
// exercise the screen without touching disk.
type Audit struct {
	mu sync.Mutex
	f  *os.File
}

// OpenAudit creates the parent directory and appends to path.
func OpenAudit(path string) (*Audit, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	f, err := openAuditFile(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	_ = f.Chmod(0o600)
	return &Audit{f: f}, nil
}

// Log writes one record. Audit failures are returned to the caller so an
// action that cannot be recorded is not silently executed.
func (a *Audit) Log(rec AuditRecord) error {
	if a == nil {
		return nil
	}
	rec.Time = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Flags = redactFlags(rec.Flags)
	rec.Path = sanitizeAuditText(rec.Path)
	rec.Command = sanitize.RedactCommandSecrets(sanitizeAuditText(rec.Command))
	rec.Reason = sanitizeAuditText(rec.Reason)
	rec.Error = sanitizeAuditText(rec.Error)
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// Close closes the log.
func (a *Audit) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}

func redactFlags(flags map[string]string) map[string]string {
	if len(flags) == 0 {
		return nil
	}
	out := make(map[string]string, len(flags))
	for key, value := range flags {
		switch {
		case containsAnyFold(key, "pass", "pwd", "secret", "token", "ticket", "key", "hash", "ntlm", "ccache", "kirbi", "krb", "pfx", "cert", "pin", "cred", "session", "cookie"):
			out[key] = "[redacted]"
		default:
			out[key] = sanitizeAuditText(value)
		}
	}
	return out
}

func sanitizeAuditText(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 4096 {
		s = s[:4096]
	}
	return s
}

func containsAnyFold(s string, parts ...string) bool {
	s = strings.ToLower(s)
	for _, part := range parts {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}
