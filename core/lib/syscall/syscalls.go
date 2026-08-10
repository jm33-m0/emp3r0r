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

	// THREADINFOCLASS values for NtSetInformationThread
	ThreadImpersonationToken = 5

	// TOKEN_INFORMATION_CLASS values for NtQueryInformationToken
	TokenUser           = 1
	TokenPrivileges     = 3
	TokenIntegrityLevel = 25

	// PS_ATTRIBUTE_NUM values for NtCreateUserProcess
	PsAttributeToken = 3

	// Process creation flags
	ProcessCreateFlagsInheritHandles = 0x00000004
)

// ---------------------------------------------------------------------------
// Process / thread / token opening
// ---------------------------------------------------------------------------

// NtOpenProcess opens a handle to a process.
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

// NtOpenProcessToken opens the primary token of a process.
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

// NtOpenThreadToken opens the token associated with a thread.
// If the thread is impersonating, that token is opened; otherwise the
// primary process token is opened.
func NtOpenThreadToken(
	table *SyscallTable,
	threadHandle windows.Handle,
	desiredAccess uint32,
	openAsSelf bool, // TRUE = use process identity, FALSE = use thread identity
) (windows.Handle, uint32, error) {
	var tokenHandle windows.Handle
	var asSelf uintptr
	if openAsSelf {
		asSelf = 1
	}

	status, err := table.InvokeSyscall(
		"NtOpenThreadToken",
		uintptr(threadHandle),
		uintptr(desiredAccess),
		asSelf,
		uintptr(unsafe.Pointer(&tokenHandle)),
	)

	return tokenHandle, status, err
}

// NtDuplicateToken duplicates an existing token handle.
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

// ---------------------------------------------------------------------------
// Thread impersonation
// ---------------------------------------------------------------------------

// NtSetInformationThread sets information on a thread object.
//
// threadInformationClass = ThreadImpersonationToken (5):
//   - To impersonate: pass pointer to token handle, length = sizeof(HANDLE)
//   - To revert: pass pointer to null handle, length = sizeof(HANDLE)
func NtSetInformationThread(
	table *SyscallTable,
	threadHandle windows.Handle,
	threadInformationClass uint32,
	threadInformation unsafe.Pointer,
	threadInformationLength uint32,
) (uint32, error) {
	return table.InvokeSyscall(
		"NtSetInformationThread",
		uintptr(threadHandle),
		uintptr(threadInformationClass),
		uintptr(threadInformation),
		uintptr(threadInformationLength),
	)
}

// ---------------------------------------------------------------------------
// Token queries
// ---------------------------------------------------------------------------

// NtQueryInformationToken retrieves information about a token.
//
// The buffer must be large enough to hold the output structure for the
// requested information class. ReturnLength receives the number of bytes
// written.
func NtQueryInformationToken(
	table *SyscallTable,
	tokenHandle windows.Handle,
	tokenInformationClass uint32,
	tokenInformation unsafe.Pointer,
	tokenInformationLength uint32,
	returnLength *uint32,
) (uint32, error) {
	return table.InvokeSyscall(
		"NtQueryInformationToken",
		uintptr(tokenHandle),
		uintptr(tokenInformationClass),
		uintptr(tokenInformation),
		uintptr(tokenInformationLength),
		uintptr(unsafe.Pointer(returnLength)),
	)
}

// ---------------------------------------------------------------------------
// Privilege adjustment
// ---------------------------------------------------------------------------

// NtAdjustPrivilegesToken enables or disables privileges in a token.
//
// When DisableAllPrivileges is true, all privileges in NewState are
// disabled and NewState is ignored (can be nil).
func NtAdjustPrivilegesToken(
	table *SyscallTable,
	tokenHandle windows.Handle,
	disableAllPrivileges bool,
	newState unsafe.Pointer,
	bufferLength uint32,
	previousState unsafe.Pointer,
	returnLength *uint32,
) (uint32, error) {
	var disableAll uintptr
	if disableAllPrivileges {
		disableAll = 1
	}

	return table.InvokeSyscall(
		"NtAdjustPrivilegesToken",
		uintptr(tokenHandle),
		disableAll,
		uintptr(newState),
		uintptr(bufferLength),
		uintptr(previousState),
		uintptr(unsafe.Pointer(returnLength)),
	)
}

// ---------------------------------------------------------------------------
// Process creation with token
// ---------------------------------------------------------------------------

// PS_ATTRIBUTE describes a single attribute for NtCreateUserProcess.
type PS_ATTRIBUTE struct {
	Attribute    uintptr  // PS_ATTRIBUTE_NUM value
	Size         uintptr  // size of the value
	Value        uintptr  // the value itself (or pointer to it for larger types)
	ReturnLength *uintptr // optional: bytes written back
}

// PS_ATTRIBUTE_LIST is passed to NtCreateUserProcess.
type PS_ATTRIBUTE_LIST struct {
	TotalLength uintptr
	Attributes  [1]PS_ATTRIBUTE // at least one; we size it via unsafe
}

// NtCreateUserProcess creates a new process running under a specified token.
//
// The token is passed via the attribute list with PsAttributeToken.
func NtCreateUserProcess(
	table *SyscallTable,
	processHandle *windows.Handle,
	threadHandle *windows.Handle,
	processDesiredAccess uint32,
	threadDesiredAccess uint32,
	processObjectAttributes *OBJECT_ATTRIBUTES,
	threadObjectAttributes *OBJECT_ATTRIBUTES,
	processFlags uint32,
	threadFlags uint32,
	processParameters unsafe.Pointer,
	createInfo unsafe.Pointer,
	attributeList unsafe.Pointer,
) (uint32, error) {
	return table.InvokeSyscall(
		"NtCreateUserProcess",
		uintptr(unsafe.Pointer(processHandle)),
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(processDesiredAccess),
		uintptr(threadDesiredAccess),
		uintptr(unsafe.Pointer(processObjectAttributes)),
		uintptr(unsafe.Pointer(threadObjectAttributes)),
		uintptr(processFlags),
		uintptr(threadFlags),
		uintptr(processParameters),
		uintptr(createInfo),
		uintptr(attributeList),
	)
}
