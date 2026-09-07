package server

// socks5_udp_test.go — UDP-ASSOCIATE DNS relay end-to-end.
//
// A SOCKS5 client opens a UDP-ASSOCIATE control connection, sends a DNS query
// datagram to the advertised UDP relay, and must receive a DNS reply datagram.
// The agent is faked: agents.SendCmd is stubbed to resolve !dns_query commands
// synchronously and deliver the reply through live.CmdResults /
// live.CmdResultsReady exactly the way the real CBOR message tunnel does.

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func startUDPAssociateTest(t *testing.T) (int, func()) {
	t.Helper()
	// A fake "connected" agent so StartSocks5Proxy passes its liveness check.
	agent := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "udp-test-agent"}
	srv, cli := net.Pipe()
	_ = cli
	ctrl := &live.AgentControl{Index: 0, Conn: srv}
	live.AgentControlMap.Store(agent, ctrl)

	// Fake agent: answer !dns_query by synthesizing a reply (it must echo the
	// question and add one A record). Parse the query's question name from the
	// base64 payload.
	agents.SendCmd = func(cmd, jobID string, a *def.Emp3r0rAgent) error {
		if a == nil || !strings.Contains(cmd, def.C2CmdDNSQuery) {
			return nil
		}
		// Extract --query <b64>
		parts := strings.Fields(cmd)
		queryB64 := ""
		for i, p := range parts {
			if p == "--query" && i+1 < len(parts) {
				queryB64 = parts[i+1]
			}
		}
		raw, err := base64.StdEncoding.DecodeString(queryB64)
		if err != nil {
			live.CmdResults.Store(jobID, "Error: bad b64")
			closeReady(jobID)
			return nil
		}
		reply := fakeAgentDNSReply(raw)
		live.CmdResults.Store(jobID, string(reply))
		closeReady(jobID)
		return nil
	}

	port := freeTCPPort(t)
	if err := StartSocks5Proxy(agent.Tag, port, "127.0.0.1"); err != nil {
		t.Fatalf("StartSocks5Proxy: %v", err)
	}
	return port, func() {
		// Stop the listener first: StopSocks5Proxy waits (ls.wg.Wait) for every
		// in-flight association handler, so no worker can still be calling
		// agents.SendCmd when we nil it below.
		_ = StopSocks5Proxy(port)
		agents.SendCmd = nil
		live.AgentControlMap.Delete(agent)
		_ = srv.Close()
	}
}

func closeReady(jobID string) {
	if chAny, ok := live.CmdResultsReady.LoadAndDelete(jobID); ok {
		if ch, ok := chAny.(chan struct{}); ok {
			close(ch)
		}
	}
}

// fakeAgentDNSReply builds a minimal DNS reply with one 10.1.2.3 A record.
func fakeAgentDNSReply(query []byte) []byte {
	// parse qname start
	pos := 12
	var qname []byte
	for {
		l := int(query[pos])
		if l == 0 {
			pos++
			break
		}
		qname = append(qname, byte(l))
		qname = append(qname, query[pos+1:pos+1+l]...)
		pos += 1 + l
	}
	// question ends with QTYPE/QCLASS
	pos += 4
	// header (ID, flags, QD=1, AN=1, NS=0, AR=0)
	out := make([]byte, 0, 64)
	out = append(out, query[0:2]...)
	out = append(out, 0x81, 0x80)
	out = append(out, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0)
	out = append(out, qname...)
	out = append(out, 0) // root
	out = append(out, 0x00, 0x01, 0x00, 0x01)
	// answer: pointer to name at offset 12
	out = append(out, 0xc0, 0x0c)
	out = append(out, 0x00, 0x01, 0x00, 0x01) // A IN
	out = append(out, 0, 0, 0, 60)            // TTL
	out = append(out, 0x00, 0x04)             // RDLEN
	out = append(out, 10, 1, 2, 3)            // 10.1.2.3
	return out
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// TestSocks5UDPAssociateDNS exercises the full UDP-ASSOCIATE path: negotiate
// the associate, get the BND relay address, send a DNS query datagram, and
// receive the wrapped DNS reply.
func TestSocks5UDPAssociateDNS(t *testing.T) {
	port, cleanup := startUDPAssociateTest(t)
	defer cleanup()

	// TCP control connection.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// greeting
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err = io.ReadFull(conn, rep); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	// UDP-ASSOCIATE 0.0.0.0:0
	if _, err = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate req: %v", err)
	}
	// reply: VER REP RSV ATYP BND
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("associate reply hdr: %v", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		t.Fatalf("associate reply: %x", hdr)
	}
	atyp := hdr[3]
	var bindHost string
	switch atyp {
	case socks5AtypIPv4:
		b := make([]byte, 4)
		if _, err = io.ReadFull(conn, b); err != nil {
			t.Fatalf("bind ipv4: %v", err)
		}
		bindHost = net.IP(b).String()
	case socks5AtypIPv6:
		b := make([]byte, 16)
		if _, err = io.ReadFull(conn, b); err != nil {
			t.Fatalf("bind ipv6: %v", err)
		}
		bindHost = net.IP(b).String()
	default:
		t.Fatalf("unexpected ATYP %d", atyp)
	}
	bp := make([]byte, 2)
	if _, err = io.ReadFull(conn, bp); err != nil {
		t.Fatalf("bind port: %v", err)
	}
	relayAddr := net.JoinHostPort(bindHost, itoa(int(binary.BigEndian.Uint16(bp))))

	// UDP socket to the advertised relay.
	udp, err := net.Dial("udp", relayAddr)
	if err != nil {
		t.Fatalf("udp dial %s: %v", relayAddr, err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(15 * time.Second))

	// Build a DNS query datagram: header + question "pivot.test" A.
	q := buildTestDNSQuery()
	// Wrap in SOCKS5 UDP header: RSV=0 FRAG=0 ATYP=IPv4 DST=1.1.1.1:53 payload
	datagram := []byte{0, 0, 0, 0x01, 1, 1, 1, 1, 0, 53}
	datagram = append(datagram, q...)
	if _, err := udp.Write(datagram); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	// Read the reply: first 4 bytes RSV/FRAG/ATYP + addr, then DNS payload.
	buf := make([]byte, 2048)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	got := buf[:n]
	dstHost, dstPort, bodyStart, ok := parseSocks5UDPAddr(got)
	if !ok {
		t.Fatalf("reply datagram unparseable: %x", got)
	}
	if dstHost != "1.1.1.1" || int(dstPort) != 53 {
		t.Fatalf("reply dst = %s:%d, want 1.1.1.1:53", dstHost, dstPort)
	}
	dnsReply := got[bodyStart:]
	if len(dnsReply) < 12 {
		t.Fatalf("short dns reply %x", dnsReply)
	}
	// ID must match the query
	var wantID uint16 = 0x4242
	if binary.BigEndian.Uint16(dnsReply[0:2]) != wantID {
		t.Fatalf("reply id = 0x%04x, want 0x%04x", binary.BigEndian.Uint16(dnsReply[0:2]), wantID)
	}
	an := binary.BigEndian.Uint16(dnsReply[6:8])
	if an != 1 {
		t.Fatalf("an = %d, want 1", an)
	}
	// The single A record 10.1.2.3 should be present.
	if !strings.Contains(string(dnsReply), string([]byte{10, 1, 2, 3})) {
		t.Fatalf("A record 10.1.2.3 not found in %x", dnsReply)
	}
}

func buildTestDNSQuery() []byte {
	q := make([]byte, 0, 64)
	q = append(q, 0x42, 0x42) // id
	q = append(q, 0x01, 0x00) // RD
	q = append(q, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	// pivot.test
	for _, l := range []string{"pivot", "test"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = append(q, 0x00, 0x01, 0x00, 0x01) // A IN
	return q
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// TestSocks5UDPAssociateDropsNonDNS verifies that a UDP datagram that is not
// addressed to port 53 is silently dropped (no reply) while the association
// stays usable.
func TestSocks5UDPAssociateDropsNonDNS(t *testing.T) {
	port, cleanup := startUDPAssociateTest(t)
	defer cleanup()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err = io.ReadFull(conn, rep); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("reply hdr: %v", err)
	}
	// read BND addr
	var addrBytes int
	switch hdr[3] {
	case socks5AtypIPv4:
		addrBytes = 4
	case socks5AtypIPv6:
		addrBytes = 16
	}
	buf := make([]byte, addrBytes+2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("bind addr: %v", err)
	}
	bindHost := net.IP(buf[:addrBytes]).String()
	relayAddr := net.JoinHostPort(bindHost, itoa(int(binary.BigEndian.Uint16(buf[addrBytes:]))))

	udp, err := net.Dial("udp", relayAddr)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(1200 * time.Millisecond))

	// non-DNS port 9999 datagram must not produce a reply
	if _, err := udp.Write([]byte{0, 0, 0, 0x01, 9, 9, 9, 9, 0x27, 0x0f, 1, 2, 3}); err != nil {
		t.Fatalf("write: %v", err)
	}
	b := make([]byte, 64)
	if n, err := udp.Read(b); err == nil {
		t.Fatalf("unexpected reply for non-DNS datagram: %x", b[:n])
	}
}

// TestSocks5UDPAssociateIsDNSOnlyConcurrency sanity: several queries can be in
// flight; each gets its own correct reply. We fire two queries and expect two
// replies (IDs echoed).
func TestSocks5UDPAssociateConcurrentQueries(t *testing.T) {
	port, cleanup := startUDPAssociateTest(t)
	defer cleanup()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err = io.ReadFull(conn, rep); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("reply hdr: %v", err)
	}
	var addrBytes int
	switch hdr[3] {
	case socks5AtypIPv4:
		addrBytes = 4
	case socks5AtypIPv6:
		addrBytes = 16
	}
	buf := make([]byte, addrBytes+2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("bind addr: %v", err)
	}
	bindHost := net.IP(buf[:addrBytes]).String()
	relayAddr := net.JoinHostPort(bindHost, itoa(int(binary.BigEndian.Uint16(buf[addrBytes:]))))

	udp, err := net.Dial("udp", relayAddr)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(20 * time.Second))

	// Fire two DNS queries with different IDs.
	wantIDs := []uint16{0x1111, 0x2222}
	for _, id := range wantIDs {
		q := buildTestDNSQuery()
		q[0], q[1] = byte(id>>8), byte(id&0xff)
		d := []byte{0, 0, 0, 0x01, 1, 1, 1, 1, 0, 53}
		d = append(d, q...)
		if _, err := udp.Write(d); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	got := map[uint16]bool{}
	for len(got) < 2 {
		b := make([]byte, 2048)
		n, err := udp.Read(b)
		if err != nil {
			t.Fatalf("read: %v (got %d ids)", err, len(got))
		}
		_, _, start, ok := parseSocks5UDPAddr(b[:n])
		if !ok {
			continue
		}
		id := binary.BigEndian.Uint16(b[start : start+2])
		got[id] = true
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Fatalf("missing reply for id 0x%04x (got %v)", id, got)
		}
	}
}

// TestSocks5UDPAssociateAgentErrorSynthesizesServfail makes the stub agent
// return a textual error (like a malformed-query NotifyC2 "Error: ..."), which
// must result in a SERVFAIL DNS reply datagram back to the client rather than
// silence.
func TestSocks5UDPAssociateAgentErrorSynthesizesServfail(t *testing.T) {
	agent := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "udp-test-agent-servfail"}
	srv, _ := net.Pipe()
	live.AgentControlMap.Store(agent, &live.AgentControl{Index: 0, Conn: srv})

	agents.SendCmd = func(cmd, jobID string, a *def.Emp3r0rAgent) error {
		if a == nil || !strings.Contains(cmd, def.C2CmdDNSQuery) {
			return nil
		}
		live.CmdResults.Store(jobID, "Error: malformed DNS query")
		closeReady(jobID)
		return nil
	}

	port := freeTCPPort(t)
	if err := StartSocks5Proxy(agent.Tag, port, "127.0.0.1"); err != nil {
		t.Fatalf("StartSocks5Proxy: %v", err)
	}
	defer func() {
		_ = StopSocks5Proxy(port)
		agents.SendCmd = nil
		live.AgentControlMap.Delete(agent)
		_ = srv.Close()
	}()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err = io.ReadFull(conn, rep); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("associate: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("reply hdr: %v", err)
	}
	var addrBytes int
	switch hdr[3] {
	case socks5AtypIPv4:
		addrBytes = 4
	case socks5AtypIPv6:
		addrBytes = 16
	}
	buf := make([]byte, addrBytes+2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("bind addr: %v", err)
	}
	bindHost := net.IP(buf[:addrBytes]).String()
	relayAddr := net.JoinHostPort(bindHost, itoa(int(binary.BigEndian.Uint16(buf[addrBytes:]))))

	udp, err := net.Dial("udp", relayAddr)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(15 * time.Second))

	q := buildTestDNSQuery()
	d := []byte{0, 0, 0, 0x01, 1, 1, 1, 1, 0, 53}
	d = append(d, q...)
	if _, err := udp.Write(d); err != nil {
		t.Fatalf("write: %v", err)
	}
	rb := make([]byte, 2048)
	n, err := udp.Read(rb)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	_, _, start, ok := parseSocks5UDPAddr(rb[:n])
	if !ok || n-start < 12 {
		t.Fatalf("bad reply datagram: %x", rb[:n])
	}
	dns := rb[start:n]
	if binary.BigEndian.Uint16(dns[0:2]) != 0x4242 {
		t.Fatalf("id mismatch: 0x%04x", binary.BigEndian.Uint16(dns[0:2]))
	}
	if rcode := binary.BigEndian.Uint16(dns[2:4]) & 0xf; rcode != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL", rcode)
	}
}
