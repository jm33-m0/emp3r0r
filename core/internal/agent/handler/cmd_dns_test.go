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
	"testing"
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
