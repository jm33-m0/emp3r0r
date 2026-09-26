package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestKCPTunQPPEndToEnd verifies the KCP C2 tunnel works with QPP obfuscation
// enabled (now the default): both ends must derive the same pad and carry bytes
// end to end unchanged through the KCP/smux/QPP stack.
func TestKCPTunQPPEndToEnd(t *testing.T) {
	if !NewConfig("", "", "1", "pw", "salt").QPP {
		t.Fatal("QPP is not enabled by default")
	}

	// Echo target behind the KCP server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	kcpPort := freeUDPPort(t)
	localPort := freeTCPPort(t)
	const password = "kcp-qpp-password"
	const salt = "kcp-qpp-salt"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- KCPTunServer(echoLn.Addr().String(), fmt.Sprintf("%d", kcpPort), password, salt, ctx, func() {})
	}()
	cliErr := make(chan error, 1)
	go func() {
		cliErr <- KCPTunClient(fmt.Sprintf("127.0.0.1:%d", kcpPort), fmt.Sprintf("%d", localPort), password, salt, ctx, func() {})
	}()

	// Wait for the client's local listener, then round-trip through the tunnel.
	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	var conn net.Conn
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("KCP client listener never came up: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("kcp-qpp-end-to-end-"), 64)
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tunnel echo mismatch: got %q", got)
	}

	select {
	case err := <-srvErr:
		t.Fatalf("KCP server exited early: %v", err)
	case err := <-cliErr:
		t.Fatalf("KCP client exited early: %v", err)
	default:
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
