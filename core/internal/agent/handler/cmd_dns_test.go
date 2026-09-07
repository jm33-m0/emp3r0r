package handler

// cmd_dns_test.go — DNS packet parsing / reply building for !dns_query.
//
// The wire helpers (parseDNSQuestion, buildDNSReply, dnsRcodeForErr) must
// round-trip a real query into a response that any DNS client would accept:
// same ID and question, QR/RA set, correct rcode, one A/AAAA RR per answer.

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// sampleDNSQuery builds a minimal single-question A query for name (relative,
// dotted) with the given id. Returns the raw packet.
func sampleDNSQuery(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 0, 64)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	b = append(b, hdr...)
	for _, label := range splitLabels(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0) // root
	var tq [4]byte
	binary.BigEndian.PutUint16(tq[0:2], qtype)
	binary.BigEndian.PutUint16(tq[2:4], 1) // CLASS IN
	b = append(b, tq[:]...)
	return b
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestParseDNSQuestion(t *testing.T) {
	raw := sampleDNSQuery(0x1234, "www.Example.COM", dnsTypeA)
	qid, qname, qtype, qstart, qend, ok := parseDNSQuestion(raw)
	if !ok {
		t.Fatal("parse failed on well-formed query")
	}
	if qid != 0x1234 {
		t.Errorf("qid = 0x%04x", qid)
	}
	if qname != "www.example.com" {
		t.Errorf("qname = %q", qname)
	}
	if qtype != dnsTypeA {
		t.Errorf("qtype = %d", qtype)
	}
	if qstart != 12 {
		t.Errorf("qstart = %d", qstart)
	}
	// header(12) + 1+3+1+7+1+3 + root(1) + 4 = 33
	if qend != len(raw) {
		t.Errorf("qend = %d, want %d", qend, len(raw))
	}
}

func TestParseDNSQuestionMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"too-short", []byte{0, 1}},
		{"truncated-name", append(sampleDNSQuery(1, "a", dnsTypeA)[:15], 0x41)}, // 63+ label overruns
		{"compression-in-question", []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
			0xc0, 0x0c, // pointer — must not appear in a question
			0x00, 0x01, 0x00, 0x01,
		}},
		{"no-qtype", func() []byte {
			b := sampleDNSQuery(1, "a", dnsTypeA)
			return b[:len(b)-2] // drop QTYPE+QCLASS
		}()},
		{"empty-name", []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
			0x00, // root name only
			0x00, 0x01, 0x00, 0x01,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, _, ok := parseDNSQuestion(tc.b); ok {
				t.Fatal("expected parse failure")
			}
		})
	}
}

// TestBuildDNSReplyRoundTrip verifies that a built reply echoes the ID and
// question and carries the expected A/AAAA records, in a shape any DNS client
// can consume (QDCOUNT=1, ANCOUNT matches, answer name is a pointer to the
// question).
func TestBuildDNSReplyRoundTrip(t *testing.T) {
	raw := sampleDNSQuery(0xbeef, "db.example", dnsTypeA)
	_, qname, qtype, qstart, qend, ok := parseDNSQuestion(raw)
	if !ok {
		t.Fatal("parse")
	}

	answers := []net.IP{net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.2").To4()}
	resp := buildDNSReply(raw, 0xbeef, qstart, qend, qtype, answers, dnsRcodeNoError)

	if len(resp) < 12 {
		t.Fatal("short reply")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0xbeef {
		t.Errorf("reply ID = 0x%04x", binary.BigEndian.Uint16(resp[0:2]))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 { // QR
		t.Error("QR not set")
	}
	if flags&0x0080 == 0 { // RA
		t.Error("RA not set")
	}
	if flags&0x000f != dnsRcodeNoError {
		t.Errorf("rcode = %d", flags&0x000f)
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		t.Errorf("QDCOUNT = %d", binary.BigEndian.Uint16(resp[4:6]))
	}
	if n := binary.BigEndian.Uint16(resp[6:8]); n != 2 {
		t.Errorf("ANCOUNT = %d", n)
	}
	// Question must be echoed verbatim.
	if string(resp[12:qend]) != string(raw[qstart:qend]) {
		t.Error("question not echoed verbatim")
	}
	// Walk the answers.
	pos := qend
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		if pos+2 > len(resp) {
			t.Fatalf("truncated answer %d at %d", i, pos)
		}
		if resp[pos] != 0xc0 || resp[pos+1] != 0x0c {
			t.Fatalf("answer %d name is not a pointer to question (got %x)", i, resp[pos:pos+2])
		}
		pos += 2
		if pos+10 > len(resp) {
			t.Fatalf("truncated answer %d fixed part", i)
		}
		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(resp) {
			t.Fatalf("truncated answer %d rdlen=%d", i, rdlen)
		}
		ip := net.IP(resp[pos : pos+rdlen])
		seen[ip.String()] = true
		pos += rdlen
	}
	if !seen["10.0.0.1"] || !seen["10.0.0.2"] {
		t.Errorf("answers = %v", seen)
	}
	if pos != len(resp) {
		t.Errorf("trailing bytes after answers: %d", len(resp)-pos)
	}

	// Same question name in a later query must let a client match by ID.
	if binary.BigEndian.Uint16(resp[0:2]) != 0xbeef {
		t.Fatal("ID mismatch")
	}
	_ = qname
}

// TestBuildDNSReplyNoAnswersForUnsupportedType: a TXT (16) question gets an
// empty NOERROR answer section — the resolver is a stub for A/AAAA only.
func TestBuildDNSReplyNoAnswersForUnsupportedType(t *testing.T) {
	raw := sampleDNSQuery(7, "example.com", 16) // TXT
	_, _, qtype, qstart, qend, ok := parseDNSQuestion(raw)
	if !ok {
		t.Fatal("parse")
	}
	resp := buildDNSReply(raw, 7, qstart, qend, qtype, nil, dnsRcodeNoError)
	if n := binary.BigEndian.Uint16(resp[6:8]); n != 0 {
		t.Errorf("ANCOUNT = %d, want 0", n)
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0x000f != dnsRcodeNoError {
		t.Errorf("rcode = %d", flags&0x000f)
	}
}

func TestDNSRcodeForErr(t *testing.T) {
	if dnsRcodeForErr(nil) != dnsRcodeNoError {
		t.Error("nil should map to NOERROR")
	}
	if dnsRcodeForErr(&net.DNSError{IsNotFound: true}) != dnsRcodeNXDomain {
		t.Error("not-found should map to NXDOMAIN")
	}
	if dnsRcodeForErr(&net.DNSError{IsTimeout: true}) != dnsRcodeServFail {
		t.Error("timeout should map to SERVFAIL")
	}
	if dnsRcodeForErr(errors.New("boom")) != dnsRcodeServFail {
		t.Error("generic error should map to SERVFAIL")
	}
}

// TestDNSBase64RoundTrip is a sanity check that the CC↔agent transport
// (base64 in, raw reply out) is coherent.
func TestDNSBase64RoundTrip(t *testing.T) {
	raw := sampleDNSQuery(0x1111, "a.example", dnsTypeA)
	b64 := base64.StdEncoding.EncodeToString(raw)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatal("base64 round trip mismatch")
	}
}

// --- Real-DNS-server tests: forwardDNSQuery must actually resolve against a
// live upstream, not just re-encode. These use an in-process authoritative
// server (github.com/miekg/dns is already a module dependency via memberlist)
// bound to 127.0.0.1, so no external network is needed.
// startTestDNSServer runs an in-process authoritative DNS server on 127.0.0.1
// answering every A query for the given records. Returns its address host:port.
func startTestDNSServer(t *testing.T, records map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		if len(r.Question) != 1 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		if ipStr, ok := records[strings.ToLower(q.Name)]; ok && q.Qtype == dns.TypeA {
			ip := net.ParseIP(ipStr).To4()
			if ip != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip,
				})
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String()
}

// TestForwardDNSQueryToRealServer proves forwardDNSQuery sends the raw query to
// the requested server and returns the server's own (authoritative) answer —
// the path that makes operator-side DNS work against an internal DC.
func TestForwardDNSQueryToRealServer(t *testing.T) {
	addr := startTestDNSServer(t, map[string]string{"corp.internal.": "10.20.30.40"})
	q := sampleDNSQuery(0x5151, "corp.internal", dnsTypeA)

	reply, err := forwardDNSQuery(q, addr)
	if err != nil {
		t.Fatalf("forwardDNSQuery: %v", err)
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0x5151 {
		t.Fatalf("reply id 0x%x", binary.BigEndian.Uint16(reply[0:2]))
	}
	if binary.BigEndian.Uint16(reply[2:4])&0x8000 == 0 {
		t.Fatal("QR not set on reply")
	}
	if !strings.Contains(string(reply), string([]byte{10, 20, 30, 40})) {
		t.Fatalf("authoritative A 10.20.30.40 missing from reply %x", reply)
	}
}

// TestForwardDNSQueryIDMismatch verifies forwardDNSQuery refuses a reply whose
// ID does not echo the query (stray/late datagram).
func TestForwardDNSQueryIDMismatch(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// echo with a mangled ID (query id +1)
		reply := append([]byte(nil), buf[:n]...)
		reply[1] = reply[1] + 1
		_, _ = pc.WriteTo(reply, addr)
	}()
	q := sampleDNSQuery(0x2222, "a.example", dnsTypeA)
	if _, err := forwardDNSQuery(q, pc.LocalAddr().String()); err == nil {
		t.Fatal("expected ID-mismatch error")
	}
}

// TestForwardDNSQueryServerDown verifies a dead upstream yields an error (and
// the caller falls back to local resolution).
func TestForwardDNSQueryServerDown(t *testing.T) {
	// Grab a port, close it, then try to forward there.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	q := sampleDNSQuery(0x3333, "dead.example", dnsTypeA)
	if _, err := forwardDNSQuery(q, addr); err == nil {
		t.Fatal("expected error forwarding to a closed port")
	}
}

// TestForwardDNSQueryRealExternal resolves a real public name through a real
// public resolver (the same path a live operator's DNS query takes). Skipped
// when the box has no internet so the suite stays hermetic offline.
func TestForwardDNSQueryRealExternal(t *testing.T) {
	// Discover an upstream from the system resolver config (e.g. 1.1.1.1, the
	// gateway DNS...). Read /etc/resolv.conf nameservers; fall back to 1.1.1.1.
	upstream := "1.1.1.1"
	if ns := firstNameserver(); ns != "" {
		upstream = ns
	}
	if !udpReachable(upstream + ":53") {
		t.Skipf("no reachable external DNS at %s", upstream)
	}

	q := sampleDNSQuery(0x4242, "google.com", dnsTypeA)
	reply, err := forwardDNSQuery(q, net.JoinHostPort(upstream, "53"))
	if err != nil {
		t.Fatalf("forwardDNSQuery(%s): %v", upstream, err)
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0x4242 {
		t.Fatalf("reply id 0x%x", binary.BigEndian.Uint16(reply[0:2]))
	}
	if binary.BigEndian.Uint16(reply[6:8]) == 0 {
		t.Fatalf("google.com A query via %s returned no answers: %x", upstream, reply)
	}
}

// firstNameserver returns the first nameserver in /etc/resolv.conf ("" if
// none or unreadable).
func firstNameserver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			return f[1]
		}
	}
	return ""
}

// udpReachable reports whether a UDP dial to addr succeeds within 2s (best
// effort: no packet round trip required, just that the socket can be created /
// the host is not hard-unreachable).
func udpReachable(addr string) bool {
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
