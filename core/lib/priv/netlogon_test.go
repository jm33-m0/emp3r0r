package priv

import (
	"strings"
	"testing"
)

// TestSessionStore exercises the platform-neutral make_token session store:
// StoreSession / GetSession / DefaultSessionName / ListSessions.
func TestSessionStore(t *testing.T) {
	// Ensure clean state for this test.
	SessionMap.Range(func(key, value any) bool {
		SessionMap.Delete(key)
		return true
	})

	sess := &LogonSession{
		User:    "jdoe",
		Domain:  "CORP",
		Token:   0x1234,
		LogonID: 0x1a2b3c4d,
	}
	if name := DefaultSessionName(sess); name != "CORP\\jdoe" {
		t.Fatalf("DefaultSessionName = %q, want CORP\\jdoe", name)
	}
	// Domain "." is treated as a local account → bare username.
	local := &LogonSession{User: "admin", Domain: "."}
	if name := DefaultSessionName(local); name != "admin" {
		t.Fatalf("DefaultSessionName(local) = %q, want admin", name)
	}

	// Explicit name.
	StoreSession("jdoe", sess)
	got, ok := GetSession("jdoe")
	if !ok || got == nil {
		t.Fatalf("GetSession(jdoe) not found after StoreSession")
	}
	if got.LogonID != 0x1a2b3c4d || got.Token != 0x1234 {
		t.Fatalf("stored session mismatch: %+v", got)
	}

	// Auto name from DefaultSessionName.
	StoreSession("", sess)
	if _, ok := GetSession("CORP\\jdoe"); !ok {
		t.Fatalf("session not stored under default name CORP\\jdoe")
	}

	// ListSessions reflects the stored entries.
	entries := ListSessions()
	found := false
	for _, e := range entries {
		if strings.Contains(e, "CORP\\jdoe") && strings.Contains(e, "luid=0x1a2b3c4d") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListSessions missing session entry: %v", entries)
	}

	// Unknown session lookup.
	if _, ok := GetSession("nope"); ok {
		t.Fatalf("GetSession(nope) should not be found")
	}
}
