package transport

import (
	"net"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestNewSecureConnIdempotent verifies that wrapping an already-wrapped
// SecureConn does not add a second encryption/framing layer. Connection setup
// helpers (EstablishC2Connection) pre-key their returned stream (e.g. to an
// ephemeral PFS session key); callers that wrap it again with NewSecureConn
// must get the very same instance back.
func TestNewSecureConnIdempotent(t *testing.T) {
	origKey := def.AESPassword
	def.AESPassword = []byte("12345678901234567890123456789012")
	defer func() { def.AESPassword = origKey }()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	first := NewSecureConn(clientConn)
	second := NewSecureConn(first)
	if second != first {
		t.Fatalf("NewSecureConn over a *SecureConn returned a new instance; double encryption/framing would break the stream")
	}

	// A raw conn must still be wrapped (not treated as an existing SecureConn).
	raw := NewSecureConn(serverConn)
	if raw == serverConn {
		t.Fatal("NewSecureConn over a raw conn must wrap it")
	}
}
