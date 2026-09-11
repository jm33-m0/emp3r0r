package server

// socks5_udp_test.go — UDP-ASSOCIATE transport mechanics.
//
// These tests exercise the SOCKS5 UDP relay framing and policy (address
// parsing, non-DNS dropping, concurrency, SERVFAIL synthesis on agent error)
// with the agent stubbed. Real DNS resolution through the pivot (agent's
// !dns_query handler forwarding to a live upstream server) is covered
// separately in socks5_dns_test.go, which runs the production handler.

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

// startUDPAssociateTest starts a SOCKS5 pivot whose agent answers !dns_query
// with a minimal canned reply (transport tests only assert framing, so the
// answer content is not what is under test). Returns the TCP port.
func startUDPAssociateTest(t *testing.T) (int, func()) {
	t.Helper()
	agent := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "udp-test-agent"}
	srv, _ := net.Pipe()
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: &live.AgentControl{Index: 0, Conn: srv}})

	agents.SendCmd = func(cmd, jobID string, a *def.Emp3r0rAgent) error {
		if a == nil || !strings.Contains(cmd, def.C2CmdDNSQuery) {
			return nil
		}
		queryB64 := flagValue(cmd, "--query")
		raw, err := base64.StdEncoding.DecodeString(queryB64)
		if err != nil {
			live.CmdResults.Store(jobID, "Error: bad b64")
			closeReady(jobID)
			return nil
		}
		live.CmdResults.Store(jobID, string(fakeAgentDNSReply(raw)))
		closeReady(jobID)
		return nil
	}

	port := freeTCPPort(t)
	if err := StartSocks5Proxy(agent.Tag, port, "127.0.0.1"); err != nil {
		t.Fatalf("StartSocks5Proxy: %v", err)
	}
	return port, func() {
		// Stop first: StopSocks5Proxy drains in-flight handlers, so none can
		// still be calling agents.SendCmd when we nil it.
		_ = StopSocks5Proxy(port)
		agents.SendCmd = nil
		live.ForgetAgent(agent.UUID)
		_ = srv.Close()
	}
}

// udpAssociate sets up a SOCKS5 UDP-ASSOCIATE: dials the pivot, greets,
// sends command 0x03 (0.0.0.0:0) and returns the control conn plus a UDP
// socket connected to the advertised relay.
func udpAssociate(t *testing.T, port int) (ctrl net.Conn, relay net.Conn) {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial pivot: %v", err)
	}
	_ = ctrl.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		ctrl.Close()
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, rep); err != nil {
		ctrl.Close()
		t.Fatalf("greeting reply: %v", err)
	}
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		ctrl.Close()
		t.Fatalf("udp-associate: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, hdr); err != nil {
		ctrl.Close()
		t.Fatalf("assoc reply hdr: %v", err)
	}
	if hdr[1] != 0 {
		ctrl.Close()
		t.Fatalf("udp-associate failed rep=%d", hdr[1])
	}
	var addrBytes int
	switch hdr[3] {
	case socks5AtypIPv4:
		addrBytes = 4
	case socks5AtypIPv6:
		addrBytes = 16
	}
	ab := make([]byte, addrBytes+2)
	if _, err := io.ReadFull(ctrl, ab); err != nil {
		ctrl.Close()
		t.Fatalf("bind addr: %v", err)
	}
	bindHost := net.IP(ab[:addrBytes]).String()
	relay, err = net.Dial("udp", net.JoinHostPort(bindHost, itoa(int(binary.BigEndian.Uint16(ab[addrBytes:])))))
	if err != nil {
		ctrl.Close()
		t.Fatalf("udp dial: %v", err)
	}
	return ctrl, relay
}

// dnsQueryDatagram wraps raw query q in a SOCKS5 UDP datagram addressed to
// ip:port (an IPv4 DNS server, the common case).
func dnsQueryDatagram(q []byte, ip net.IP, port uint16) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	d := []byte{0, 0, 0, 0x01}
	d = append(d, ip4...)
	d = append(d, byte(port>>8), byte(port&0xff))
	return append(d, q...)
}

// TestSocks5UDPAssociateDropsNonDNS: UDP datagrams that do not carry a DNS
// query (a query has QR=0 and exactly one parseable question) are dropped with
// no reply, while the association stays usable.
func TestSocks5UDPAssociateDropsNonDNS(t *testing.T) {
	port, cleanup := startUDPAssociateTest(t)
	defer cleanup()
	ctrl, relay := udpAssociate(t, port)
	defer ctrl.Close()
	defer relay.Close()

	// Non-DNS: garbage payload, QR=1 (response), 2 questions, etc.
	cases := [][]byte{
		{0, 0, 0, 0x01, 9, 9, 9, 9, 0x27, 0x0f, 1, 2, 3},    // <12 bytes payload
		{0, 0, 0, 0x01, 9, 9, 9, 9, 0x27, 0x0f, 0x81, 0x80}, // QR=1 (a response)
	}
	for i, c := range cases {
		if _, err := relay.Write(c); err != nil {
			t.Fatalf("case %d write: %v", i, err)
		}
		_ = relay.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b := make([]byte, 64)
		if n, err := relay.Read(b); err == nil {
			t.Fatalf("case %d unexpected reply: %x", i, b[:n])
		}
	}
}

// TestSocks5UDPAssociateConcurrentQueries: several queries in flight each get
// a reply echoing their own ID.
func TestSocks5UDPAssociateConcurrentQueries(t *testing.T) {
	port, cleanup := startUDPAssociateTest(t)
	defer cleanup()
	ctrl, relay := udpAssociate(t, port)
	defer ctrl.Close()
	defer relay.Close()
	_ = relay.SetDeadline(time.Now().Add(20 * time.Second))

	wantIDs := []uint16{0x1111, 0x2222}
	for _, id := range wantIDs {
		q := buildTestDNSQuery()
		q[0], q[1] = byte(id>>8), byte(id&0xff)
		if _, err := relay.Write(dnsQueryDatagram(q, net.ParseIP("1.1.1.1"), 53)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	got := map[uint16]bool{}
	for len(got) < len(wantIDs) {
		b := make([]byte, 2048)
		n, err := relay.Read(b)
		if err != nil {
			t.Fatalf("read: %v (got %v)", err, got)
		}
		_, _, start, ok := parseSocks5UDPAddr(b[:n])
		if !ok || n-start < 2 {
			continue
		}
		got[binary.BigEndian.Uint16(b[start:start+2])] = true
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Fatalf("missing reply for id 0x%04x (got %v)", id, got)
		}
	}
}

// TestSocks5UDPAssociateAgentErrorSynthesizesServfail: when the agent returns
// a textual error (e.g. malformed query), the CC must answer the client with a
// SERVFAIL DNS reply rather than silence.
func TestSocks5UDPAssociateAgentErrorSynthesizesServfail(t *testing.T) {
	agent := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "udp-test-agent-servfail"}
	srv, _ := net.Pipe()
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: &live.AgentControl{Index: 0, Conn: srv}})

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
		live.ForgetAgent(agent.UUID)
		_ = srv.Close()
	}()

	ctrl, relay := udpAssociate(t, port)
	defer ctrl.Close()
	defer relay.Close()
	_ = relay.SetDeadline(time.Now().Add(20 * time.Second))

	q := buildTestDNSQuery() // id 0x4242
	if _, err := relay.Write(dnsQueryDatagram(q, net.ParseIP("1.1.1.1"), 53)); err != nil {
		t.Fatalf("write: %v", err)
	}
	b := make([]byte, 2048)
	n, err := relay.Read(b)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	_, _, start, ok := parseSocks5UDPAddr(b[:n])
	if !ok || n-start < 12 {
		t.Fatalf("bad reply datagram: %x", b[:n])
	}
	dns := b[start:n]
	if binary.BigEndian.Uint16(dns[0:2]) != 0x4242 {
		t.Fatalf("id mismatch: 0x%04x", binary.BigEndian.Uint16(dns[0:2]))
	}
	if rcode := binary.BigEndian.Uint16(dns[2:4]) & 0xf; rcode != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL", rcode)
	}
}

// --- helpers shared with socks5_dns_test.go / protocol tests ----------------

func closeReady(jobID string) {
	if chAny, ok := live.CmdResultsReady.LoadAndDelete(jobID); ok {
		if ch, ok := chAny.(chan struct{}); ok {
			close(ch)
		}
	}
}

// fakeAgentDNSReply builds a minimal valid DNS reply (one A record 10.1.2.3)
// for transport-level tests that stub the agent. Real resolution is covered in
// socks5_dns_test.go.
func fakeAgentDNSReply(query []byte) []byte {
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
	out := make([]byte, 0, 64)
	out = append(out, query[0:2]...) // id
	out = append(out, 0x81, 0x80)    // QR RA RD
	out = append(out, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0)
	out = append(out, qname...)
	out = append(out, 0)
	out = append(out, 0x00, 0x01, 0x00, 0x01) // QTYPE/QCLASS
	out = append(out, 0xc0, 0x0c)             // name pointer
	out = append(out, 0x00, 0x01, 0x00, 0x01) // A IN
	out = append(out, 0, 0, 0, 60)            // TTL
	out = append(out, 0x00, 0x04)             // RDLEN
	out = append(out, 10, 1, 2, 3)            // 10.1.2.3
	return out
}

// flagValue returns the value following flag in a command line ("" if absent).
func flagValue(cmd, flag string) string {
	parts := strings.Fields(cmd)
	for i, p := range parts {
		if p == flag && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
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

func buildTestDNSQuery() []byte {
	q := make([]byte, 0, 64)
	q = append(q, 0x42, 0x42) // id
	q = append(q, 0x01, 0x00) // RD
	q = append(q, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
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
