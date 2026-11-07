//go:build unix

package mcp

import (
	"os"
	"syscall"
)

// openAuditFile opens an append-only audit log without following a symlink at
// the final path component. A pre-existing symlink would otherwise redirect
// every audit record.
func openAuditFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
}
