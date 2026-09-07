package server

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
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

			cmd, host, port, atyp, err := readSocks5Request(serverConn)
			if err != nil {
				t.Fatalf("readSocks5Request: %v", err)
			}
			if cmd != tc.wantCmd {
				t.Errorf("cmd = 0x%02x, want 0x%02x", cmd, tc.wantCmd)
			}
			wantHost, wantPort, _ := net.SplitHostPort(tc.want)
			if host != wantHost {
				t.Errorf("host = %q, want %q", host, wantHost)
			}
			if int(port) != atoiSafe(wantPort) {
				t.Errorf("port = %d, want %s", port, wantPort)
			}
			if atyp == 0 {
				t.Errorf("atyp not set")
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
	if _, _, _, _, err := readSocks5Request(serverConn); err == nil {
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

func atoiSafe(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

// TestSocks5ReplyFormat checks the wire format of CONNECT replies.
func TestSocks5ReplyFormat(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- socks5Reply(clientConn, socks5RepConnectionRefused, "0.0.0.0", 0)
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

// --- UDP-ASSOCIATE (DNS relay) protocol tests --------------------------------

// TestSocks5UDPAddrParse exercises parseSocks5UDPAddr on well-formed and
// truncated datagrams for every address type.
func TestSocks5UDPAddrParse(t *testing.T) {
	// [RSV RSV FRAG ATYP ...]
	cases := []struct {
		name      string
		b         []byte
		wantHost  string
		wantPort  int
		wantStart int
		wantOK    bool
	}{
		{
			name:     "ipv4",
			b:        []byte{0, 0, 0, 1, 10, 0, 0, 1, 0, 53, 'D', 'N', 'S'},
			wantHost: "10.0.0.1", wantPort: 53, wantStart: 10, wantOK: true,
		},
		{
			name:     "domain",
			b:        []byte{0, 0, 0, 3, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 53, 'x'},
			wantHost: "example", wantPort: 53, wantStart: 14, wantOK: true,
		},
		{
			name: "ipv6",
			b: append([]byte{0, 0, 0, 4},
				append([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, []byte{0, 53, 'q'}...)...),
			wantHost: "2001:db8::1", wantPort: 53, wantStart: 22, wantOK: true,
		},
		{name: "short", b: []byte{0, 0, 0}, wantOK: false},
		{name: "bad-atyp", b: []byte{0, 0, 0, 9, 0, 0}, wantOK: false},
		{name: "truncated-domain", b: []byte{0, 0, 0, 3, 10, 'a'}, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, start, ok := parseSocks5UDPAddr(tc.b)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if host != tc.wantHost || int(port) != tc.wantPort || start != tc.wantStart {
				t.Fatalf("got %q:%d@%d, want %q:%d@%d", host, port, start, tc.wantHost, tc.wantPort, tc.wantStart)
			}
		})
	}
}

// TestSocks5UDPDatagramRoundTrip verifies buildSocks5UDPDatagram output is
// parseable and addresses the original destination.
func TestSocks5UDPDatagramRoundTrip(t *testing.T) {
	payload := []byte{0xab, 0xcd, 0xef}
	out := buildSocks5UDPDatagram("10.1.2.3", 53, payload)
	if len(out) != 4+4+2+len(payload) {
		t.Fatalf("unexpected datagram length %d", len(out))
	}
	host, port, start, ok := parseSocks5UDPAddr(out)
	if !ok {
		t.Fatal("built datagram did not parse")
	}
	if host != "10.1.2.3" || int(port) != 53 || start != 10 {
		t.Fatalf("round trip mismatch: %q:%d start=%d", host, port, start)
	}
	if string(out[start:]) != string(payload) {
		t.Fatalf("payload mismatch: %x", out[start:])
	}
}

// TestSocks5ReplyAddrType checks that socks5Reply picks the ATYP that matches
// the bind address given (IPv4 by default, IPv6 when given an IPv6 literal).
func TestSocks5ReplyAddrType(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- socks5Reply(clientConn, socks5RepSuccess, "::1", 1080) }()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(serverConn, hdr); err != nil {
		t.Fatalf("read hdr: %v", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 || hdr[2] != 0x00 || hdr[3] != socks5AtypIPv6 {
		t.Fatalf("bad reply header: %x", hdr)
	}
	addr := make([]byte, 16+2)
	if _, err := io.ReadFull(serverConn, addr); err != nil {
		t.Fatalf("read addr: %v", err)
	}
	if net.IP(addr[:16]).String() != "::1" {
		t.Fatalf("bind addr = %s", net.IP(addr[:16]))
	}
	if binary.BigEndian.Uint16(addr[16:]) != 1080 {
		t.Fatalf("port = %d", binary.BigEndian.Uint16(addr[16:]))
	}
	if err := <-errCh; err != nil {
		t.Fatalf("socks5Reply: %v", err)
	}
}

// TestSocks5UDPAssociateRequestParsing checks that a UDP-ASSOCIATE request is
// parsed with the right command byte and address.
func TestSocks5UDPAssociateRequestParsing(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		// VER CMD(0x03) RSV ATYP(IPv4) 0.0.0.0:0  (client usually sends 0.0.0.0:0)
		_, _ = clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		clientConn.Close()
	}()

	cmd, host, port, atyp, err := readSocks5Request(serverConn)
	if err != nil {
		t.Fatalf("readSocks5Request: %v", err)
	}
	if cmd != socks5CmdUDPAssociate {
		t.Fatalf("cmd = 0x%02x, want 0x03", cmd)
	}
	if atyp != socks5AtypIPv4 || host != "0.0.0.0" || port != 0 {
		t.Fatalf("got atyp=%d host=%q port=%d", atyp, host, port)
	}
}

// TestServfailDNSReply checks that a synthesized SERVFAIL echoes the query ID
// and question, and carries the SERVFAIL rcode.
func TestServfailDNSReply(t *testing.T) {
	q := []byte{
		0xab, 0xcd, // id
		0x01, 0x00, // RD
		0x00, 0x01, 0, 0, 0, 0, 0, 0, // QD=1
		3, 'f', 'o', 'o', 0, // foo.
		0x00, 0x01, 0x00, 0x01, // A IN
	}
	reply := servfailDNSReply(q)
	if len(reply) == 0 {
		t.Fatal("empty reply")
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0xabcd {
		t.Fatalf("id = 0x%04x", binary.BigEndian.Uint16(reply[0:2]))
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&0x8000 == 0 || flags&0x0080 == 0 {
		t.Fatalf("QR/RA not set: 0x%04x", flags)
	}
	if flags&0x000f != 0x0002 {
		t.Fatalf("rcode = 0x%x, want SERVFAIL", flags&0x000f)
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 1 {
		t.Fatalf("QDCOUNT = %d", binary.BigEndian.Uint16(reply[4:6]))
	}
	// question echoed
	if string(reply[12:]) != string(q[12:]) {
		t.Fatalf("question not echoed: %x vs %x", reply[12:], q[12:])
	}
}
