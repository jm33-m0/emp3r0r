package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// websocketConnPair returns the two ends of a real websocket connection, each
// wrapped as a net.Conn exactly like the operator message tunnel. Using the
// real coder/websocket net.Conn matters here because its deadline semantics are
// what the regression test exercises.
func websocketConnPair(t *testing.T) (serverConn, clientConn net.Conn, cleanup func()) {
	t.Helper()
	serverCh := make(chan net.Conn, 1)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		serverCh <- websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		<-done
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		cancel()
		srv.Close()
		t.Fatalf("dial websocket: %v", err)
	}
	clientConn = websocket.NetConn(ctx, ws, websocket.MessageBinary)

	select {
	case serverConn = <-serverCh:
	case <-ctx.Done():
		cancel()
		srv.Close()
		t.Fatalf("server websocket not accepted: %v", ctx.Err())
	}

	cleanup = func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		close(done)
		cancel()
		srv.Close()
	}
	return serverConn, clientConn, cleanup
}

// TestOperatorBroadcastNotPoisonedByWriteDeadline is the regression test for
// the "only the first agent reports knock knock" bug.
//
// A targeted relay (fwdMsgToOperator) used to set an absolute write deadline on
// the shared operator websocket and never clear it. coder/websocket's net.Conn
// marks itself write-expired once that deadline fires while idle, so every
// subsequent broadcast (operatorBroadcastPrintf -> fwdMsg2Operators) failed
// with "failed to write: context deadline exceeded": the second agent's
// knock-knock never reached the operator even though it appeared in the list.
func TestOperatorBroadcastNotPoisonedByWriteDeadline(t *testing.T) {
	serverConn, clientConn, cleanup := websocketConnPair(t)
	defer cleanup()

	origTimeout := operatorWriteTimeout
	operatorWriteTimeout = 100 * time.Millisecond
	defer func() { operatorWriteTimeout = origTimeout }()

	const session = "deadline-test-operator"
	OPERATORS.Store(session, &operator_t{sessionID: session, conn: serverConn})
	defer OPERATORS.Delete(session)

	received := make(chan def.MsgTunData, 8)
	go func() {
		dec := cbor.NewDecoder(clientConn)
		for {
			var m def.MsgTunData
			if err := dec.Decode(&m); err != nil {
				return
			}
			received <- m
		}
	}()

	// A targeted relay must reach the operator.
	if err := fwdMsgToOperator(session, def.MsgTunData{Tag: "relay"}); err != nil {
		t.Fatalf("fwdMsgToOperator: %v", err)
	}
	select {
	case m := <-received:
		if m.Tag != "relay" {
			t.Fatalf("got tag %q, want relay", m.Tag)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("targeted relay frame not received")
	}

	// Poison the shared tunnel exactly as a leaked absolute write deadline does:
	// arm a deadline that fires while the connection is idle. coder/websocket's
	// net.Conn then permanently marks itself write-expired until the next
	// SetWriteDeadline call.
	if err := serverConn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("arm write deadline: %v", err)
	}
	time.Sleep(3 * operatorWriteTimeout)

	// The broadcast must recover by arming (and clearing) its own deadline.
	if err := fwdMsg2Operators(def.MsgTunData{Tag: "SUCCESS", Response: []byte("knock knock")}); err != nil {
		t.Fatalf("broadcast after a leaked write deadline expired: %v", err)
	}
	select {
	case m := <-received:
		if m.Tag != "SUCCESS" {
			t.Fatalf("got tag %q, want SUCCESS", m.Tag)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broadcast frame not received after a leaked write deadline expired")
	}
}
