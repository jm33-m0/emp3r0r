package server

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestSocks5RequestParsing exercises the minimal RFC1928 request parser over
// real pipe connections for IPv4, domain and IPv6 destinations.
func TestSocks5RequestParsing(t *testing.T) {
	cases := []struct {
		name    string
		req     []byte
		wantCmd byte
		want    string
	}{
		{
			name:    "ipv4",
			req:     []byte{0x05, 0x01, 0x00, 0x01, 10, 1, 2, 3, 0x1f, 0x90},
			wantCmd: 0x01,
			want:    "10.1.2.3:8080",
		},
		{
			name:    "domain",
			req:     []byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50},
			wantCmd: 0x01,
			want:    "example.com:80",
		},
		{
			name: "ipv6",
			req: []byte{
				0x05, 0x01, 0x00, 0x04,
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x35,
			},
			wantCmd: 0x01,
			want:    "[2001:db8::1]:53",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				_, err := clientConn.Write(tc.req)
				clientConn.Close()
				errCh <- err
			}()

			cmd, target, err := readSocks5Request(serverConn)
			if err != nil {
				t.Fatalf("readSocks5Request: %v", err)
			}
			if cmd != tc.wantCmd {
				t.Errorf("cmd = 0x%02x, want 0x%02x", cmd, tc.wantCmd)
			}
			if target != tc.want {
				t.Errorf("target = %q, want %q", target, tc.want)
			}
			<-errCh
		})
	}
}

// TestSocks5RequestParsingErrors exercises rejection paths that fail before the
// full request is consumed (the pipe is closed by the writer, so no deadlock).
func TestSocks5RequestParsingErrors(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	go func() {
		// bad version in request header; close right after so a short read
		// cannot block forever on the pipe.
		_, _ = clientConn.Write([]byte{0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
		clientConn.Close()
	}()
	if _, _, err := readSocks5Request(serverConn); err == nil {
		t.Fatal("expected error for wrong SOCKS version")
	}
}

// TestSocks5Greeting verifies negotiation accepts no-auth and rejects methods.
func TestSocks5Greeting(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	}()
	methods, err := readSocks5Greeting(serverConn)
	if err != nil {
		t.Fatalf("readSocks5Greeting: %v", err)
	}
	if !socks5SupportsNoAuth(methods) {
		t.Fatal("no-auth should be supported")
	}
	if socks5SupportsNoAuth([]byte{0x01, 0x02}) {
		t.Fatal("no-auth should not be reported when absent")
	}
}

// TestSocks5ReplyFormat checks the wire format of CONNECT replies.
func TestSocks5ReplyFormat(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5Reply(clientConn, socks5RepConnectionRefused)
	}()
	buf := make([]byte, 10)
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	// VER=5 REP=0x05 RSV=0 ATYP=1 BND=0.0.0.0:0
	want := []byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for i := range want {
		if buf[i] != want[i] {
			t.Fatalf("reply[%d] = 0x%02x, want 0x%02x", i, buf[i], want[i])
		}
	}
	if err := <-errCh; err != nil {
		t.Fatalf("socks5Reply: %v", err)
	}
}

// TestSocks5ManagerPortValidation checks listener lifecycle error paths that do
// not require a live agent.
func TestSocks5ManagerPortValidation(t *testing.T) {
	if err := StartSocks5Proxy("", 0, ""); err == nil {
		t.Fatal("expected error for port 0")
	}
	if err := StartSocks5Proxy("", 70000, ""); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
	if err := StopSocks5Proxy(1); err == nil {
		t.Fatal("expected error stopping a listener that does not exist")
	}
	StopAllSocks5Proxies() // must be a no-op and not panic
}

// TestSocks5HandshakeTimeout ensures a stalled client does not hang the server.
func TestSocks5HandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// client connects but never sends a greeting
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(2 * time.Second)
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	_ = conn.SetDeadline(start.Add(300 * time.Millisecond))
	if _, err := readSocks5Greeting(conn); err == nil {
		t.Fatal("expected greeting read to time out")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("greeting read took %v, deadline not honored", elapsed)
	}
}
