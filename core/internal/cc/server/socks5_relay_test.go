package server

// socks5_relay_test.go — idle-timeout & teardown of the SOCKS5 pivot relay.
//
// A relay whose legs stay silent (client died without FIN, or agent stream
// stalled) must be torn down so the goroutine, pending entry and bookkeeping
// do not linger forever. Active relays must not be killed.

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns a connected (server, client) pair over loopback TCP.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		conn net.Conn
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return r.conn, client
}

// isOpen reports whether the connection still accepts data (true) or has been
// closed by the peer (false). A 60ms read deadline is used.
func isOpen(t *testing.T, c net.Conn) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if n > 0 {
		// unexpected data on a silent leg — treat as open and drain-free
		return true
	}
	if err == nil {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false // EOF / reset -> closed
}

func TestRelaySOCKS5IdleTeardown(t *testing.T) {
	origIdle, origWatch := socks5RelayIdleTimeout, socks5RelayWatchInterval
	socks5RelayIdleTimeout = 250 * time.Millisecond
	socks5RelayWatchInterval = 40 * time.Millisecond
	defer func() {
		socks5RelayIdleTimeout, socks5RelayWatchInterval = origIdle, origWatch
	}()

	sockSrv, sockClient := tcpPair(t)
	streamSrv, streamClient := tcpPair(t)
	defer sockClient.Close()
	defer streamClient.Close()

	done := make(chan struct{})
	go func() {
		relaySOCKS5Stream(sockSrv, streamSrv, "idle-test")
		close(done)
	}()

	// Both legs silent: the relay must tear itself down and close both ends.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !isOpen(t, sockClient) && !isOpen(t, streamClient) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if isOpen(t, sockClient) {
		t.Fatal("operator-side connection still open after idle timeout")
	}
	if isOpen(t, streamClient) {
		t.Fatal("agent stream still open after idle timeout")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relaySOCKS5Stream did not return after idle teardown")
	}
}

func TestRelaySOCKS5ActivityKeepsAlive(t *testing.T) {
	origIdle, origWatch := socks5RelayIdleTimeout, socks5RelayWatchInterval
	socks5RelayIdleTimeout = 300 * time.Millisecond
	socks5RelayWatchInterval = 40 * time.Millisecond
	defer func() {
		socks5RelayIdleTimeout, socks5RelayWatchInterval = origIdle, origWatch
	}()

	sockSrv, sockClient := tcpPair(t)
	streamSrv, streamClient := tcpPair(t)
	defer sockClient.Close()
	defer streamClient.Close()

	// Drain the agent-stream side so the relay's writes never block.
	go func() { _, _ = io.Copy(io.Discard, streamClient) }()

	done := make(chan struct{})
	go func() {
		relaySOCKS5Stream(sockSrv, streamSrv, "keepalive-test")
		close(done)
	}()

	// Send data well past the idle window; the relay must stay alive.
	for i := 0; i < 10; i++ {
		if _, err := sockClient.Write([]byte("x")); err != nil {
			t.Fatalf("write while active: %v", err)
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !isOpen(t, sockClient) {
		t.Fatal("relay torn down despite continuous activity")
	}

	// Now go silent: idle teardown should kick in.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && isOpen(t, sockClient) {
		time.Sleep(50 * time.Millisecond)
	}
	if isOpen(t, sockClient) {
		t.Fatal("relay not torn down after going idle")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relaySOCKS5Stream did not return")
	}
}

// TestRelaySOCKS5EndOnPeerClose verifies a normal close (client FIN) still
// tears the relay down immediately, not only after the idle timeout.
func TestRelaySOCKS5EndOnPeerClose(t *testing.T) {
	origIdle, origWatch := socks5RelayIdleTimeout, socks5RelayWatchInterval
	socks5RelayIdleTimeout = 1 * time.Hour // must NOT be the idle timer doing the work
	socks5RelayWatchInterval = 40 * time.Millisecond
	defer func() {
		socks5RelayIdleTimeout, socks5RelayWatchInterval = origIdle, origWatch
	}()

	sockSrv, sockClient := tcpPair(t)
	streamSrv, streamClient := tcpPair(t)
	defer streamClient.Close()

	done := make(chan struct{})
	go func() {
		relaySOCKS5Stream(sockSrv, streamSrv, "close-test")
		close(done)
	}()

	// Operator hangs up.
	_ = sockClient.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end when the operator side closed")
	}
	if isOpen(t, streamClient) {
		t.Fatal("agent stream not closed after peer hung up")
	}
}
