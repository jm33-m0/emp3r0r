//go:build unix

package mcp

import (
	"os"
	"syscall"
)

// hasMultipleLinks reports whether info names an inode reachable through more
// than one directory entry. Writing such a file could modify content outside
// the workspace root.
func hasMultipleLinks(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

// openRead opens a workspace file without following a symlink at the final
// path component.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
