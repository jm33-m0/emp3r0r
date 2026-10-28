package tor

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/pkg/agenttransport"
)

// TestDialThroughSOCKS5 exercises the example with a local SOCKS5 server. The
// server ignores the requested .onion target and relays to a local echo
// listener, so the test needs no Tor daemon.
func TestDialThroughSOCKS5(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	defer socks.Close()
	go serveSOCKSTo(t, socks, echo.Addr().String())

	conn, err := (dialer{}).Dial(context.Background(), agenttransport.Target{
		Address: "example.onion:80",
		Options: map[string]string{"socks5": socks.Addr().String()},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestDialRequiresAddress(t *testing.T) {
	if _, err := (dialer{}).Dial(context.Background(), agenttransport.Target{}); err == nil {
		t.Fatal("Dial accepted an empty address")
	}
}

// serveSOCKSTo is a minimal no-auth SOCKS5 CONNECT server. It accepts any
// target and connects to fixedAddr instead.
func serveSOCKSTo(t *testing.T, listener net.Listener, fixedAddr string) {
	t.Helper()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			if !socksHandshake(conn) {
				return
			}
			target, err := net.Dial("tcp", fixedAddr)
			if err != nil {
				return
			}
			defer target.Close()
			// Success reply with an IPv4 zero address.
			_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			go func() { _, _ = io.Copy(target, conn) }()
			_, _ = io.Copy(conn, target)
		}(conn)
	}
}

func socksHandshake(conn net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return false
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return false
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 || req[1] != 1 {
		return false
	}
	var addrLen int
	switch req[3] {
	case 1:
		addrLen = 4
	case 3:
		one := make([]byte, 1)
		if _, err := io.ReadFull(conn, one); err != nil {
			return false
		}
		addrLen = int(one[0])
	case 4:
		addrLen = 16
	default:
		return false
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		return false
	}
	return true
}

// ensure the example registers under the expected name and can be looked up.
func TestRegistered(t *testing.T) {
	d, err := agenttransport.Get(Name)
	if err != nil {
		t.Fatalf("Get(%q): %v", Name, err)
	}
	if !strings.EqualFold(d.Name(), Name) {
		t.Fatalf("name = %q", d.Name())
	}
}
