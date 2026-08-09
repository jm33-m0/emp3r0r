//go:build windows

package priv

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// ensureTable sets syscall.RuntimeSyscallTable if it is not already
// initialized, so that functions relying on the global (Whoami,
// EnablePrivilege, ExecuteAsToken, GetTokenUserSid, etc.) work in tests.
func ensureTable(t *testing.T) {
	t.Helper()
	if syscall.RuntimeSyscallTable != nil {
		return
	}
	table, err := syscall.InitializeSyscallTable()
	if err != nil {
		t.Fatalf("InitializeSyscallTable failed: %v", err)
	}
	syscall.RuntimeSyscallTable = table
}

func TestWhoami(t *testing.T) {
	ensureTable(t)
	out, err := Whoami()
	if err != nil {
		t.Fatalf("Whoami failed: %v", err)
	}
	if out == "" {
		t.Fatalf("Whoami returned empty string")
	}
	t.Logf("Whoami output: %s", out)
}

func TestGetTokenUserSid(t *testing.T) {
	ensureTable(t)
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatalf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	sid, err := GetTokenUserSid(windows.Handle(token))
	if err != nil {
		t.Fatalf("GetTokenUserSid failed: %v", err)
	}
	if sid == "" {
		t.Fatalf("GetTokenUserSid returned empty SID")
	}
	t.Logf("Current Process User SID: %s", sid)
}

func TestGetTokenIntegrityLevel(t *testing.T) {
	ensureTable(t)
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatalf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	integrity, err := GetTokenIntegrityLevel(windows.Handle(token))
	if err != nil {
		t.Fatalf("GetTokenIntegrityLevel failed: %v", err)
	}
	t.Logf("Current Process Integrity Level SID: %s", integrity)
}

func TestGetTokenPrivileges(t *testing.T) {
	ensureTable(t)
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatalf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	privs, err := GetTokenPrivileges(windows.Handle(token))
	if err != nil {
		t.Fatalf("GetTokenPrivileges failed: %v", err)
	}
	t.Logf("Current Process Privileges (%d found): %v", len(privs), privs)
}

func TestDuplicateSystemTokenAndExecute(t *testing.T) {
	ensureTable(t)
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token)
	if err != nil {
		t.Fatalf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	hDupToken, err := DuplicateSystemToken(syscall.RuntimeSyscallTable, windows.Handle(token))
	if err != nil {
		t.Fatalf("DuplicateSystemToken failed: %v", err)
	}
	defer windows.CloseHandle(hDupToken)

	if hDupToken == 0 {
		t.Fatalf("DuplicateSystemToken returned 0 handle")
	}
	t.Logf("Duplicated Token Handle: 0x%x", hDupToken)

	actionExecuted := false
	err = ExecuteAsToken(hDupToken, func() error {
		actionExecuted = true
		return nil
	})
	if err != nil {
		t.Fatalf("ExecuteAsToken failed: %v", err)
	}
	if !actionExecuted {
		t.Fatalf("ExecuteAsToken action did not execute")
	}
}

func TestStealTokenCurrentProcess(t *testing.T) {
	ensureTable(t)
	currentPID := windows.GetCurrentProcessId()

	hToken, err := StealToken(syscall.RuntimeSyscallTable, currentPID)
	if err != nil {
		t.Fatalf("StealToken for current process failed: %v", err)
	}
	defer windows.CloseHandle(hToken)

	if hToken == 0 {
		t.Fatalf("StealToken returned 0 handle")
	}
	t.Logf("StealToken succeeded with duplicated token handle: 0x%x", hToken)
}
