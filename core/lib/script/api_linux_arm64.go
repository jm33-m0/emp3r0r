//go:build linux && arm64

package script

import "golang.org/x/sys/unix"

func registerArchSyscalls() {
	registerSyscalls(map[string]uintptr{
		"accept":          unix.SYS_ACCEPT,
		"mmap":            unix.SYS_MMAP,
		"getrlimit":       unix.SYS_GETRLIMIT,
		"sync_file_range": unix.SYS_SYNC_FILE_RANGE,
	})
}
