//go:build windows

package mcp

import (
	"os"
	"syscall"
)

// hasMultipleLinks reports whether path has more than one hardlink on Windows.
func hasMultipleLinks(path string, _ os.FileInfo) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(
		p,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return false
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &d); err != nil {
		return false
	}
	return d.NumberOfLinks > 1
}

func openRead(path string) (*os.File, error) { return os.Open(path) }
