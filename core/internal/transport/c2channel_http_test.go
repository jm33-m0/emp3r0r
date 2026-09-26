package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// nopReadWriteCloser stands in for a transport whose underlying connection does
// not track authentication (e.g. a raw TLS or h2connection).
type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }

// TestActiveHTTPServerSessionRequiresAuth guards the CVE-2026-61554 rate
// limiter bypass. A client can register a session with a chosen id before any
// authentication, so only a session that completed the C2 handshake may be
// exempt from the connection rate limiters.
func TestActiveHTTPServerSessionRequiresAuth(t *testing.T) {
	const sessionID = "c2channel-http-auth-test"
	defer serverSessions.Delete(sessionID)

	config := &def.MalleableHTTPConfig{
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
	}
	stream := newHTTPServerStream(sessionID)
	defer stream.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", "sessionID="+sessionID)

	if IsActiveHTTPServerSession(req, config) {
		t.Fatalf("unauthenticated session must not bypass the rate limiter")
	}
	stream.MarkAuthenticated()
	if !IsActiveHTTPServerSession(req, config) {
		t.Fatalf("authenticated session should bypass the rate limiter")
	}
}

// TestGenericStreamTransportTracksAuth verifies the auth state is a
// transport-level property: the wrapper records it for every transport (h2 and
// raw TLS included) and forwards it to an auth-aware wrapped session.
func TestGenericStreamTransportTracksAuth(t *testing.T) {
	plain := NewStreamTransport(nopReadWriteCloser{}, "1.2.3.4:1").(*GenericStreamTransport)
	if plain.IsAuthenticated() {
		t.Fatalf("new transport must start unauthenticated")
	}
	plain.MarkAuthenticated()
	if !plain.IsAuthenticated() {
		t.Fatalf("transport should be authenticated after MarkAuthenticated")
	}

	const sessionID = "c2channel-generic-auth-test"
	defer serverSessions.Delete(sessionID)
	stream := newHTTPServerStream(sessionID)
	defer stream.Close()

	wrapped := NewStreamTransport(stream, "1.2.3.4:2").(*GenericStreamTransport)
	wrapped.MarkAuthenticated()
	if !wrapped.IsAuthenticated() || !stream.IsAuthenticated() {
		t.Fatalf("auth must be recorded on both the wrapper and the wrapped session")
	}
}
