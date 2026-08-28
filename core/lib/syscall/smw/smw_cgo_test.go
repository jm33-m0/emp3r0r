//go:build windows && amd64 && cgo

package smw_test

import (
	"testing"
	"unsafe"

	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall/smw"
	"golang.org/x/sys/windows"
)

// TestCallSpoofedSyscall exercises the SilentMoonwalk desync path directly
// with a real NT syscall (NtOpenProcess on the current process).
func TestCallSpoofedSyscall(t *testing.T) {
	table, err := ntsyscall.InitializeSyscallTable()
	if err != nil {
		t.Fatalf("InitializeSyscallTable failed: %v", err)
	}

	info, found := table.GetSyscall("NtOpenProcess")
	if !found {
		t.Fatalf("NtOpenProcess not found in SyscallTable")
	}

	var hProcess windows.Handle
	var clientID struct {
		UniqueProcess windows.Handle
		UniqueThread  windows.Handle
	}
	clientID.UniqueProcess = windows.Handle(windows.GetCurrentProcessId())

	objectAttributes := struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}{Length: uint32(unsafe.Sizeof(struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}{}))}

	status, err := smw.Call(info.SSN, info.GadgetAddr, []uintptr{
		uintptr(unsafe.Pointer(&hProcess)),
		uintptr(windows.PROCESS_QUERY_LIMITED_INFORMATION),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(unsafe.Pointer(&clientID)),
	})
	if err != nil {
		t.Fatalf("smw.Call failed: %v", err)
	}
	if status != ntsyscall.STATUS_SUCCESS {
		t.Fatalf("spoofed NtOpenProcess status: 0x%08X", status)
	}
	if hProcess == 0 {
		t.Fatalf("spoofed NtOpenProcess returned invalid handle")
	}
	defer windows.CloseHandle(hProcess)
	t.Logf("spoofed NtOpenProcess OK (handle 0x%x)", hProcess)
}

// TestCallTooManyArgs verifies the 8-argument guard.
func TestCallTooManyArgs(t *testing.T) {
	_, err := smw.Call(0, 0, make([]uintptr, 9))
	if err == nil {
		t.Fatalf("expected error for 9 arguments")
	}
}
