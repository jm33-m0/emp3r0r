//go:build windows

package modules

import (
	"os"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
)

// ensureSyscallTable initializes the global syscall table (MakeToken relies
// on syscall.RuntimeSyscallTable for NtDuplicateToken).
func ensureSyscallTable(t *testing.T) {
	t.Helper()
	if _, err := syscall.GetRuntimeSyscallTable(); err != nil {
		t.Fatalf("GetRuntimeSyscallTable: %v", err)
	}
}

// netlogonE2EEnabled reports whether netlogon integration tests are
// explicitly enabled. They create real logon sessions via LogonUserW and
// talk to LSASS, which is not available in CI; run them locally with
// EMP3R0R_NETLOGON_E2E=1.
func netlogonE2EEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EMP3R0R_NETLOGON_E2E"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// TestResolveTokenKeyUserSession verifies that --user triggers get-or-create
// of a make_token session (session stored + token registered) and that the
// returned key resolves through executeWithToken.
func TestResolveTokenKeyUserSession(t *testing.T) {
	if !netlogonE2EEnabled() {
		t.Skip("set EMP3R0R_NETLOGON_E2E=1 to run netlogon integration tests")
	}
	ensureSyscallTable(t)

	// Clean the session/token stores for a deterministic test.
	priv.SessionMap.Range(func(key, value any) bool {
		priv.SessionMap.Delete(key)
		return true
	})
	priv.TokenMap.Range(func(key, value any) bool {
		priv.TokenMap.Delete(key)
		return true
	})

	inv := def.ResolvedInvocation{SessionUser: "CORP/jdoe"}
	key, err := resolveTokenKey(inv)
	if err != nil {
		t.Fatalf("resolveTokenKey(user): %v", err)
	}
	if key != "CORP/jdoe" {
		t.Fatalf("resolveTokenKey returned key %q, want CORP/jdoe", key)
	}

	// Session must be cached and its token registered under the session name.
	session, ok := priv.GetSession("CORP/jdoe")
	if !ok || session == nil {
		t.Fatalf("make_token session not stored")
	}
	if _, ok := priv.TokenMap.Load("CORP/jdoe"); !ok {
		t.Fatalf("session token not registered in TokenMap")
	}
	if err := executeWithToken(key, func(tok uintptr) error {
		if tok == 0 {
			t.Fatalf("executeWithToken returned zero token for session")
		}
		return nil
	}); err != nil {
		t.Fatalf("executeWithToken(session): %v", err)
	}

	// Re-resolving with the same user string must reuse the existing session.
	session1, _ := priv.GetSession("CORP/jdoe")
	key2, err := resolveTokenKey(def.ResolvedInvocation{SessionUser: "CORP/jdoe"})
	if err != nil {
		t.Fatalf("resolveTokenKey second call: %v", err)
	}
	session2, _ := priv.GetSession("CORP/jdoe")
	if key2 != "CORP/jdoe" || session1 != session2 {
		t.Fatalf("resolveTokenKey did not reuse the session (key2=%q)", key2)
	}

	// Bare user (no domain) resolves to a local session name.
	key3, err := resolveTokenKey(def.ResolvedInvocation{SessionUser: "localadmin"})
	if err != nil {
		t.Fatalf("resolveTokenKey(localuser): %v", err)
	}
	if key3 != "localadmin" {
		t.Fatalf("local session key = %q, want localadmin", key3)
	}
}

// TestResolveTokenKeyUnknownToken verifies that a bad --token key is rejected.
func TestResolveTokenKeyUnknownToken(t *testing.T) {
	_, err := resolveTokenKey(def.ResolvedInvocation{Token: "S-1-5-99-unknown"})
	if err == nil {
		t.Fatalf("expected error for unknown token key")
	}
}
