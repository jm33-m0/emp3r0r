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

// TestSessionKeyConditionalClear verifies that a closing tunnel only clears
// the session key it negotiated and never wipes a newer key installed by a
// racing reconnect or a second in-process tunnel. This is the regression test
// for the intermittent SOCKS5-pivot relay failure (agent-side SecureConn
// decryption error right after the PFS handshake) seen when full-stack tests
// ran back-to-back: an abandoned tunnel's teardown used to clear the fresh
// tunnel's key, so the relay fell back to the PSK while the C2 still re-keyed
// with the PFS key.
func TestSessionKeyConditionalClear(t *testing.T) {
	if got := getCurrentSessionKey(); got != nil {
		t.Fatalf("expected no session key at start, got %x", got)
	}

	tunnelA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tunnelB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	// Tunnel A negotiates its key.
	setCurrentSessionKey(tunnelA)

	// Tunnel B reconnects and installs a newer key (racing A's teardown).
	setCurrentSessionKey(tunnelB)

	// A's teardown must NOT clear B's key.
	clearCurrentSessionKeyIf(tunnelA)
	if got := getCurrentSessionKey(); !bytes.Equal(got, tunnelB) {
		t.Fatalf("stale tunnel cleared a newer session key: got %x want %x", got, tunnelB)
	}

	// B's own teardown clears its key.
	clearCurrentSessionKeyIf(tunnelB)
	if got := getCurrentSessionKey(); got != nil {
		t.Fatalf("owning tunnel did not clear its key: got %x", got)
	}

	// Clearing with an empty key is a no-op (defensive).
	setCurrentSessionKey(tunnelA)
	clearCurrentSessionKeyIf(nil)
	if got := getCurrentSessionKey(); !bytes.Equal(got, tunnelA) {
		t.Fatalf("nil guard cleared the key: got %x", got)
	}
	clearCurrentSessionKey()
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
