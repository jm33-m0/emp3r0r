package tun2socks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// minimalSOCKS5Server implements just enough of RFC 1928 (no-auth, CONNECT)
// to accept a sing socks.Client handshake and then echoes bytes back.
type minimalSOCKS5Server struct {
	ln       net.Listener
	done     chan struct{}
	accepted chan net.Conn
}

func startMinimalSOCKS5Server(t *testing.T) *minimalSOCKS5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &minimalSOCKS5Server{ln: ln, done: make(chan struct{}), accepted: make(chan net.Conn, 1)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted <- conn
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() {
		close(s.done)
		_ = ln.Close()
	})
	return s
}

func (s *minimalSOCKS5Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	atyp := req[3]
	switch atyp {
	case 1:
		if _, err := io.CopyN(io.Discard, conn, 4); err != nil {
			return
		}
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(lb[0])); err != nil {
			return
		}
	case 4:
		if _, err := io.CopyN(io.Discard, conn, 16); err != nil {
			return
		}
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return
	}
	_ = binary.BigEndian.Uint16(port)
	// success reply: 0.0.0.0:0
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_, _ = io.Copy(conn, conn)
}

func (s *minimalSOCKS5Server) addr() string { return s.ln.Addr().String() }

func TestPivotHandlerRelay(t *testing.T) {
	srv := startMinimalSOCKS5Server(t)

	h := newPivotHandler(srv.addr(), "test")
	clientSide, gvisorSide := net.Pipe()
	defer clientSide.Close()
	defer gvisorSide.Close()

	dst := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 9999)
	go h.relayTCP(context.Background(), gvisorSide, dst)

	// The pivot dials our SOCKS5 server and relays; the echo server should
	// bounce our bytes back.
	payload := []byte("hello-tun2socks")
	go func() { _, _ = clientSide.Write(payload) }()

	buf := make([]byte, len(payload))
	_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
	_ = clientSide.Close()
	_ = gvisorSide.Close()
}
