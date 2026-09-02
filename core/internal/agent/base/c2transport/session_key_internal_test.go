package c2transport

import (
	"bytes"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestSessionKeyLifecycle verifies the agent-side ephemeral PFS session key
// holder: it is published when the tunnel handshake completes, read back by
// EstablishC2Connection for auxiliary streams, and dropped when the session
// ends (before the next check-in, which must use the static PSK).
func TestSessionKeyLifecycle(t *testing.T) {
	if got := getCurrentSessionKey(); got != nil {
		t.Fatalf("expected no session key at start, got %x", got)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	setCurrentSessionKey(key)

	got := getCurrentSessionKey()
	if !bytes.Equal(got, key) {
		t.Fatalf("session key mismatch: got %x want %x", got, key)
	}

	// Mutating the original buffer must not corrupt the stored copy.
	for i := range key {
		key[i] = 0x00
	}
	if got := getCurrentSessionKey(); !bytes.Equal(got, []byte("0123456789abcdef0123456789abcdef")) {
		t.Fatalf("stored session key was aliased by caller buffer: %x", got)
	}

	clearCurrentSessionKey()
	if got := getCurrentSessionKey(); got != nil {
		t.Fatalf("session key not cleared after teardown: %x", got)
	}

	// Setting an empty key clears as well.
	setCurrentSessionKey([]byte("0123456789abcdef0123456789abcdef"))
	setCurrentSessionKey(nil)
	if got := getCurrentSessionKey(); got != nil {
		t.Fatalf("empty session key did not clear holder: %x", got)
	}
}

// TestIsBootstrapRoute verifies that check-in and message-tunnel connections
// always start on the per-build PSK, while auxiliary routes (FTP/WWW/proxy)
// are candidates for the ephemeral PFS session-key switch.
func TestIsBootstrapRoute(t *testing.T) {
	common.RuntimeConfig = &def.Config{
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}

	for _, c := range []struct {
		caps []string
		want bool
	}{
		{caps: []string{"c2-checkin"}, want: true},
		{caps: []string{"c2-msg"}, want: true},
		{caps: []string{"c2-checkin", "c2-msg"}, want: true},
		{caps: []string{"c2-ftp"}, want: false},
		{caps: []string{"c2-www"}, want: false},
		{caps: []string{"c2-proxy"}, want: false},
		{caps: []string{"c2-www", "c2-checkin"}, want: true},
	} {
		if got := isBootstrapRoute(c.caps); got != c.want {
			t.Errorf("isBootstrapRoute(%v) = %v, want %v", c.caps, got, c.want)
		}
	}
}
