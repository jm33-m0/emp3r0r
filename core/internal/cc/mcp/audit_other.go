//go:build !unix

package mcp

import "os"

// openAuditFile opens an append-only audit log. The symlink guard is only
// available on Unix hosts, where the C2 runs.
func openAuditFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
