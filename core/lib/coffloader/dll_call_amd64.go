//go:build windows && amd64

package coffloader

import (
	"syscall"
	"unsafe"
)

func callLoadAndRun(fn uintptr, buf []byte, callback uintptr) uintptr {
	r0, _, _ := syscall.SyscallN(fn, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), callback)
	return r0
}
