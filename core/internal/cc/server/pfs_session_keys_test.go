package server

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// TestPFSSessionKeyRegistry verifies the in-memory per-agent registry that lets
// the dispatcher re-key auxiliary streams (FTP/WWW/proxy) to the ephemeral PFS
// session key negotiated on the agent's message tunnel.
func TestPFSSessionKeyRegistry(t *testing.T) {
	uuid := "reg-test-agent"
	key := []byte("0123456789abcdef0123456789abcdef")
	other := []byte("fedcba9876543210fedcba9876543210")

	if _, ok := lookupPFSSessionKey(uuid); ok {
		t.Fatal("expected no session key for unknown agent")
	}

	rememberPFSSessionKey(uuid, key)
	got, ok := lookupPFSSessionKey(uuid)
	if !ok || !bytes.Equal(got, key) {
		t.Fatalf("lookup after remember: ok=%v key=%x", ok, got)
	}

	// Mutating the input after remember must not corrupt the stored key.
	for i := range key {
		key[i] = 0x00
	}
	if got, _ := lookupPFSSessionKey(uuid); !bytes.Equal(got, []byte("0123456789abcdef0123456789abcdef")) {
		t.Fatalf("registry aliased caller buffer: %x", got)
	}

	// Re-keying (fresh tunnel handshake) replaces the entry.
	rememberPFSSessionKey(uuid, other)
	if got, _ := lookupPFSSessionKey(uuid); !bytes.Equal(got, other) {
		t.Fatalf("re-key did not replace session key: %x", got)
	}

	// Teardown of the OLD tunnel (holding the old key) must NOT wipe the newer
	// session key that already replaced it.
	forgetPFSSessionKey(uuid, key)
	if _, ok := lookupPFSSessionKey(uuid); !ok {
		t.Fatal("teardown with stale key wiped the newer session key")
	}

	// Teardown of the CURRENT tunnel (holding the current key) drops it.
	forgetPFSSessionKey(uuid, other)
	if _, ok := lookupPFSSessionKey(uuid); ok {
		t.Fatal("session key not dropped at tunnel teardown")
	}

	// Empty UUID / key are no-ops and cannot crash.
	rememberPFSSessionKey("", other)
	rememberPFSSessionKey(uuid, nil)
	forgetPFSSessionKey("", other)
}

// TestMaybeRekeyAuxStream drives a SecureConn pair over a pipe and verifies
// that the dispatcher switches auxiliary streams (FTP/WWW/proxy) to the
// agent's ephemeral PFS session key right after the MsgAuth envelope, while
// bootstrap routes (check-in / message tunnel) stay on the static per-build
// PSK until their own handshake completes.
func TestMaybeRekeyAuxStream(t *testing.T) {
	live.RuntimeConfig = &def.Config{
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}

	const agentUUID = "rekey-test-agent"
	sessionKey := []byte("abcdef0123456789abcdef0123456789")
	rememberPFSSessionKey(agentUUID, sessionKey)
	defer forgetPFSSessionKey(agentUUID, sessionKey)

	roundTrip := func(t *testing.T, service string, clientKey []byte, wantOK bool) {
		t.Helper()
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		serverSecure := transport.NewSecureConn(serverConn)
		clientSecure := transport.NewSecureConn(clientConn)

		// The dispatcher re-keys its SecureConn after reading the MsgAuth
		// envelope (which itself was always encrypted with the per-build PSK).
		maybeRekeyAuxStream(service, serverSecure, agentUUID)
		clientSecure.SetKey(clientKey)

		payload := []byte(fmt.Sprintf("payload-for-%s", service))
		errCh := make(chan error, 1)
		go func() {
			_, err := clientSecure.Write(payload)
			errCh <- err
		}()

		buf := make([]byte, len(payload)+1)
		n, err := serverSecure.Read(buf)
		if !wantOK {
			if err == nil {
				t.Fatalf("service %q: expected decryption to fail with wrong key, but read %q", service, buf[:n])
			}
			return
		}
		if err != nil {
			t.Fatalf("service %q: read after re-key failed: %v", service, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("service %q: payload mismatch: got %q want %q", service, buf[:n], payload)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("service %q: client write failed: %v", service, err)
		}
	}

	// Auxiliary routes are re-keyed: client must encrypt with the session key.
	staticPSK := def.AESPassword
	for _, svc := range []string{"c2-ftp", "c2-www", "c2-proxy"} {
		roundTrip(t, svc, sessionKey, true)
		// And a client still using the static PSK must now fail: proof that the
		// dispatcher really switched keys instead of merely toggling a flag.
		roundTrip(t, svc, staticPSK, false)
	}

	// Bootstrap routes are never re-keyed here: the static PSK still works and
	// the session key must NOT.
	roundTrip(t, "c2-checkin", staticPSK, true)
	roundTrip(t, "c2-checkin", sessionKey, false)
	roundTrip(t, "c2-msg", staticPSK, true)
	roundTrip(t, "c2-msg", sessionKey, false)
}

// TestProcessKeyExchangeNoMidSessionReKey verifies that the ephemeral PFS
// session key is established exactly once per tunnel: a hello carrying a fresh
// ECDH offer after PFS is established is rejected (mid-session key change is
// not allowed), while the initial handshake still derives the key and keep-alive
// hellos (no ephemeral key) still get a random reply.
func TestProcessKeyExchangeNoMidSessionReKey(t *testing.T) {
	keyPair, err := transport.GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("GenerateEphemeralKeyPair: %v", err)
	}
	offer := transport.SerializePublicKey(&keyPair.PublicKey)
	if len(offer) == 0 {
		t.Fatal("empty ephemeral key offer")
	}

	// Initial handshake: a key offer is accepted and yields a session key plus
	// the server's ephemeral public key as reply.
	initial := &def.MsgTunData{Tag: "t", AgentUUID: "uuid-1", EphemPublicKey: offer}
	reply, sk, err := processKeyExchange(initial, false)
	if err != nil {
		t.Fatalf("initial handshake failed: %v", err)
	}
	if len(sk) == 0 {
		t.Fatal("initial handshake derived no session key")
	}
	if _, err := transport.DeserializePublicKey(reply); err != nil {
		t.Fatalf("initial handshake reply is not a valid ephemeral public key: %v", err)
	}

	// Mid-session: the same offer must be rejected — the session key is pinned
	// for the lifetime of the tunnel.
	reKey := &def.MsgTunData{Tag: "t", AgentUUID: "uuid-1", EphemPublicKey: offer}
	reply2, sk2, err := processKeyExchange(reKey, true)
	if err == nil {
		t.Fatalf("mid-session re-key was not rejected (reply=%d bytes, key=%d bytes)", len(reply2), len(sk2))
	}
	if sk2 != nil {
		t.Fatal("mid-session re-key derived a session key")
	}

	// Keep-alive hello (no ephemeral key) after PFS is still fine.
	reply3, sk3, err := processKeyExchange(&def.MsgTunData{Tag: "t", AgentUUID: "uuid-1"}, true)
	if err != nil {
		t.Fatalf("keep-alive after PFS failed: %v", err)
	}
	if len(reply3) == 0 || sk3 != nil {
		t.Fatalf("keep-alive should reply with random data and no session key (reply=%d, key=%d)", len(reply3), len(sk3))
	}
}
