//go:build windows

package syscall

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Security Impersonation Levels and Token Types
const (
	SecurityImpersonation uint32 = 2
	TokenImpersonation    uint32 = 2
)

// NtOpenProcess opens a handle to a process using syscall
func NtOpenProcess(
	table *SyscallTable,
	desiredAccess uint32,
	targetPID uint32,
) (windows.Handle, uint32, error) {
	var processHandle windows.Handle

	clientID := CLIENT_ID{
		UniqueProcess: windows.Handle(uintptr(targetPID)),
		UniqueThread:  0,
	}

	objectAttributes := OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
	}

	status, err := table.InvokeSyscall(
		"NtOpenProcess",
		uintptr(unsafe.Pointer(&processHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(unsafe.Pointer(&clientID)),
	)

	return processHandle, status, err
}

// NtOpenProcessToken opens a handle to a process token using syscall
func NtOpenProcessToken(
	table *SyscallTable,
	processHandle windows.Handle,
	desiredAccess uint32,
) (windows.Handle, uint32, error) {
	var tokenHandle windows.Handle

	status, err := table.InvokeSyscall(
		"NtOpenProcessToken",
		uintptr(processHandle),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&tokenHandle)),
	)

	return tokenHandle, status, err
}

// NtDuplicateToken duplicates an existing token handle using syscall
func NtDuplicateToken(
	table *SyscallTable,
	existingTokenHandle windows.Handle,
	desiredAccess uint32,
	objectAttributes *OBJECT_ATTRIBUTES,
	effectiveOnly bool,
	tokenType uint32,
) (windows.Handle, uint32, error) {
	var newTokenHandle windows.Handle
	var effOnly uintptr
	if effectiveOnly {
		effOnly = 1
	}

	status, err := table.InvokeSyscall(
		"NtDuplicateToken",
		uintptr(existingTokenHandle),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(objectAttributes)),
		effOnly,
		uintptr(tokenType),
		uintptr(unsafe.Pointer(&newTokenHandle)),
	)

	return newTokenHandle, status, err
}
