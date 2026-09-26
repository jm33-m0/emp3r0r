package transport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

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

// TestActiveHTTPServerSessionEdgeCases covers malformed and unknown inputs: a
// nil config, a missing session id, an unknown id, and a header-configured
// profile must all fail closed.
func TestActiveHTTPServerSessionEdgeCases(t *testing.T) {
	cookieCfg := &def.MalleableHTTPConfig{SessionHeader: "Cookie", SessionValue: "sessionID=%s"}
	headerCfg := &def.MalleableHTTPConfig{SessionHeader: "X-Session", SessionValue: "sessionID=%s"}

	if IsActiveHTTPServerSession(httptest.NewRequest(http.MethodGet, "/", nil), nil) {
		t.Fatal("nil config must not be active")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if IsActiveHTTPServerSession(req, cookieCfg) || IsActiveHTTPServerSession(req, headerCfg) {
		t.Fatal("request without a session id must not be active")
	}

	req.Header.Set("Cookie", "sessionID=does-not-exist")
	if IsActiveHTTPServerSession(req, cookieCfg) {
		t.Fatal("unknown session must not be active")
	}

	const sessionID = "c2channel-edge-case"
	defer serverSessions.Delete(sessionID)
	stream := newHTTPServerStream(sessionID)
	defer stream.Close()

	req.Header.Set("Cookie", "sessionID="+sessionID)
	if IsActiveHTTPServerSession(req, cookieCfg) {
		t.Fatal("unauthenticated session must not be active")
	}
	// A header-configured profile must not read the cookie.
	if IsActiveHTTPServerSession(req, headerCfg) {
		t.Fatal("header-configured lookup must not read the cookie")
	}

	stream.MarkAuthenticated()
	if !IsActiveHTTPServerSession(req, cookieCfg) {
		t.Fatal("authenticated session must be active")
	}
}

// TestAuthStateConcurrent stresses the shared auth flag the way the transport
// does: the dispatcher marks it while HTTP handler goroutines read it.
func TestAuthStateConcurrent(t *testing.T) {
	const sessionID = "c2channel-auth-concurrent"
	defer serverSessions.Delete(sessionID)
	stream := newHTTPServerStream(sessionID)
	defer stream.Close()
	wrapped := NewStreamTransport(stream, "1.2.3.4:9").(*GenericStreamTransport)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream.MarkAuthenticated()
			wrapped.MarkAuthenticated()
			if !stream.IsAuthenticated() || !wrapped.IsAuthenticated() {
				t.Errorf("auth state lost during concurrent access")
			}
		}()
	}
	wg.Wait()

	if !stream.IsAuthenticated() || !wrapped.IsAuthenticated() {
		t.Fatal("auth state lost after concurrent access")
	}
}

// TestAnonymousBodyReadTimeout verifies an unauthenticated session cannot pin a
// handler goroutine by dribbling a POST body.
func TestAnonymousBodyReadTimeout(t *testing.T) {
	const sessionID = "c2channel-slow-body"
	defer serverSessions.Delete(sessionID)

	orig := anonymousBodyReadTimeout
	anonymousBodyReadTimeout = 200 * time.Millisecond
	defer func() { anonymousBodyReadTimeout = orig }()

	stream := newHTTPServerStream(sessionID)
	defer stream.Close()

	config := &def.MalleableHTTPConfig{
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=1",
		CloseHeader:   "Cookie",
		CloseValue:    "teardown=1",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = HandleHTTPServerSession(w, req, config)
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Declare a large body, send one byte, then stall.
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nCookie: sessionID=%s\r\nContent-Length: 100000\r\n\r\n", sessionID); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write partial body: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, _ = http.ReadResponse(bufio.NewReader(conn), nil)
	elapsed := time.Since(start)

	// A working fix responds (413) well before the client-side 3s deadline.
	if elapsed > 2*time.Second {
		t.Fatalf("anonymous slow body was not bounded: still open after %v", elapsed)
	}
}

// TestAuthenticatedBodyReadUnbounded confirms the anonymous deadline is not
// applied to verified sessions, so large transfers over slow links still work.
func TestAuthenticatedBodyReadUnbounded(t *testing.T) {
	const sessionID = "c2channel-auth-body"
	defer serverSessions.Delete(sessionID)

	orig := anonymousBodyReadTimeout
	anonymousBodyReadTimeout = 200 * time.Millisecond
	defer func() { anonymousBodyReadTimeout = orig }()

	stream := newHTTPServerStream(sessionID)
	defer stream.Close()
	stream.MarkAuthenticated()

	config := &def.MalleableHTTPConfig{
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=1",
		CloseHeader:   "Cookie",
		CloseValue:    "teardown=1",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = HandleHTTPServerSession(w, req, config)
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nCookie: sessionID=%s\r\nContent-Length: 100000\r\n\r\n", sessionID); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write partial body: %v", err)
	}

	// Wait longer than the anonymous timeout: a verified session must still be
	// waiting for the rest of the body rather than returning early.
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(make([]byte, 128))
	var netErr net.Error
	if err == nil {
		t.Fatalf("authenticated slow body was bounded (server responded early)")
	}
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected the client-side deadline to fire, got %v", err)
	}
}

// TestHTTPPollTimingJitter guards the grammar fix: neither the long-poll hold
// nor the client re-poll delay may be a fixed constant.
func TestHTTPPollTimingJitter(t *testing.T) {
	holds := map[time.Duration]bool{}
	for range 32 {
		h := randomPollHold()
		if h < httpPollHoldMin || h >= httpPollHoldMax {
			t.Fatalf("poll hold %v outside [%v, %v)", h, httpPollHoldMin, httpPollHoldMax)
		}
		holds[h] = true
	}
	if len(holds) < 2 {
		t.Fatalf("poll hold not jittered: %v", holds)
	}

	blinks := map[time.Duration]bool{}
	for range 32 {
		b := randomBlink()
		if b < httpBlinkMin || b >= httpBlinkMax {
			t.Fatalf("blink %v outside [%v, %v)", b, httpBlinkMin, httpBlinkMax)
		}
		blinks[b] = true
	}
	if len(blinks) < 2 {
		t.Fatalf("blink not jittered: %v", blinks)
	}
}

// TestHTTPServerSessionClosesViaConfiguredHeader verifies teardown works over
// the configured header/cookie rather than a distinctive DELETE method.
func TestHTTPServerSessionClosesViaConfiguredHeader(t *testing.T) {
	const sessionID = "c2channel-http-close-header"
	defer serverSessions.Delete(sessionID)

	config := &def.MalleableHTTPConfig{
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=1",
		CloseHeader:   "Cookie",
		CloseValue:    "close=1",
	}
	stream := newHTTPServerStream(sessionID)
	defer stream.Close()

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Cookie", "sessionID="+sessionID+"; close=1")

	rec := httptest.NewRecorder()
	if _, err := HandleHTTPServerSession(rec, req, config); err != ErrPollingRequest {
		t.Fatalf("close request returned %v, want ErrPollingRequest", err)
	}
	val, ok := serverSessions.Load(sessionID)
	if !ok {
		return // reaped immediately is also acceptable
	}
	s, ok := val.(*HTTPServerStream)
	if !ok || s == nil {
		t.Fatalf("unexpected session value %T", val)
	}
	if !s.isClosing() {
		t.Fatal("session was not marked closing by the close header")
	}
}

// TestHTTPServerSessionCloseRequiresToken verifies a bare DELETE (no close
// token) no longer tears a session down, so the method is not a magic close.
func TestHTTPServerSessionCloseRequiresToken(t *testing.T) {
	const sessionID = "c2channel-http-close-requires-token"
	defer serverSessions.Delete(sessionID)

	config := &def.MalleableHTTPConfig{
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		CloseHeader:   "Cookie",
		CloseValue:    "close=1",
	}
	stream := newHTTPServerStream(sessionID)
	defer stream.Close()

	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Cookie", "sessionID="+sessionID)
	rec := httptest.NewRecorder()
	_, _ = HandleHTTPServerSession(rec, req, config)
	if stream.isClosing() {
		t.Fatal("DELETE without the configured close token must not close the session")
	}
}
