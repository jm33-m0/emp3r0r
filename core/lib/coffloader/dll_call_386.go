//go:build windows && 386

package coffloader

import "unsafe"

// cdeclCall3 is implemented in dll_call_386.s.
func cdeclCall3(fn, a, b, c uintptr) uintptr

func callLoadAndRun(fn uintptr, buf []byte, callback uintptr) uintptr {
	return cdeclCall3(fn, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), callback)
}
