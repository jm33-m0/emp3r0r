//go:build windows

package priv

import (
	"os"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// ensureTable initializes the global syscall table once via
// GetRuntimeSyscallTable, so that functions relying on the global (Whoami,
// EnablePrivilege, ExecuteAsToken, GetTokenUserSid, etc.) work in tests.
func ensureTable(t *testing.T) {
	t.Helper()
	if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
		t.Fatalf("GetRuntimeSyscallTable failed: %v", err)
	}
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

func TestGetTokenLogonID(t *testing.T) {
	ensureTable(t)
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatalf("OpenProcessToken failed: %v", err)
	}
	defer token.Close()

	luid, err := GetTokenLogonID(windows.Handle(token))
	if err != nil {
		t.Fatalf("GetTokenLogonID failed: %v", err)
	}
	if luid.LowPart == 0 && luid.HighPart == 0 {
		t.Fatalf("GetTokenLogonID returned zero LUID")
	}
	t.Logf("Current logon session LUID: 0x%08x", luidToUint64(luid))
}

func TestMakeTokenSession(t *testing.T) {
	if !netlogonE2EEnabled() {
		t.Skip("set EMP3R0R_NETLOGON_E2E=1 to run netlogon integration tests")
	}
	ensureTable(t)

	// LogonUserW(LOGON32_LOGON_NEW_CREDENTIALS) accepts a dummy password: it
	// clones the current token and maps the supplied credentials for outbound
	// connections. Use the current username so the environment is realistic.
	user := os.Getenv("USERNAME")
	if user == "" {
		user = "testuser"
	}
	session, err := MakeToken(user, ".", "DummyP4ss!")
	if err != nil {
		t.Skipf("MakeToken unavailable in this environment: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(session.Token))

	if session.Token == 0 {
		t.Fatalf("MakeToken returned zero token handle")
	}
	if session.LogonID == 0 {
		t.Fatalf("MakeToken returned zero logon LUID")
	}
	t.Logf("make_token session: user=%s domain=%s luid=0x%08x", session.User, session.Domain, session.LogonID)

	// The duplicated token must be usable for thread impersonation.
	impersonated := false
	err = ExecuteAsToken(windows.Handle(session.Token), func() error {
		impersonated = true
		return nil
	})
	if err != nil {
		t.Fatalf("ExecuteAsToken with session token failed: %v", err)
	}
	if !impersonated {
		t.Fatalf("ExecuteAsToken action did not run")
	}

	// Session must be addressable through the universal token store.
	StoreSession("test", session)
	RegisterSessionToken(session)
	raw, ok := TokenMap.Load("test")
	if !ok {
		t.Fatalf("session token not registered in TokenMap")
	}
	if _, ok := raw.(windows.Handle); !ok {
		t.Fatalf("TokenMap entry is not a windows.Handle: %T", raw)
	}
	TokenMap.Delete("test")
}
