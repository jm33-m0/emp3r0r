package server

// socks5_dns_test.go — DNS through the SOCKS5 pivot, end to end, with a real
// upstream DNS server and the agent's real !dns_query handler.
//
// Previously the UDP-ASSOCIATE DNS test faked the agent's answer, so it could
// pass even though live DNS was broken: the CC discarded the DNS server the
// operator's client had addressed (e.g. a corporate DC) and the agent's own
// resolver does not know that DC's internal names. This test reproduces the
// real chain with no fake answers:
//
//	proxy-ns-style client --UDP ASSOCIATE--> CC pivot
//	       CC sends !dns_query --query <raw> --server <dst> to the agent
//	       agent forwards the raw query to the real upstream DNS server
//	       authoritative reply flows back to the client
//
// The "agent" is the real agent-side handler invoked in-process: agents.SendCmd
// is stubbed only to *deliver* the command to that handler (instead of over a
// TLS tunnel), and the handler's reply is read back off def.CCMsgConn, which we
// point at a pipe. Everything else — query parsing, --server forwarding, reply
// validation — is production code.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/miekg/dns"
)

// startRealDNSRelayServer spins up a pivot whose "agent" is the production
// agent-side DNS handler, reached in-process via agents.SendCmd. It returns the
// pivot TCP port and a cleanup func.
func startRealDNSRelayServer(t *testing.T) (int, func()) {
	t.Helper()

	agent := &def.Emp3r0rAgent{UUID: uuid.NewString(), Tag: "dns-agent"}
	// The handler's reply goes through send2CC -> def.CCMsgConn. Point it at one
	// end of a pipe; the other end is decoded like the real message tunnel.
	agentPipe, ccPipe := net.Pipe()
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: &live.AgentControl{Index: 0, Conn: ccPipe}})
	origCCMsgConn := def.CCMsgConn
	def.CCMsgConn = agentPipe

	// Route the handler's reply back through live.CmdResults, exactly as the
	// message-tunnel handler does for a !dns_query job response.
	replyReader := func() {
		dec := cbor.NewDecoder(ccPipe)
		for {
			var msg def.MsgTunData
			if err := dec.Decode(&msg); err != nil {
				return
			}
			live.CmdResults.Store(msg.JobID, string(msg.Response))
			if chAny, ok := live.CmdResultsReady.LoadAndDelete(msg.JobID); ok {
				if ch, ok := chAny.(chan struct{}); ok {
					close(ch)
				}
			}
		}
	}
	go replyReader()

	// agents.SendCmd is the transport: instead of a TLS tunnel it feeds the
	// command to the real agent-side command dispatcher. The handler reads the
	// query/server flags and runs forwardDNSQuery against the real upstream.
	agents.SendCmd = func(cmd, jobID string, a *def.Emp3r0rAgent) error {
		if a == nil || !strings.Contains(cmd, def.C2CmdDNSQuery) {
			return nil
		}
		parts := strings.Fields(cmd)
		var queryB64, server string
		for i, p := range parts {
			if p == "--query" && i+1 < len(parts) {
				queryB64 = parts[i+1]
			}
			if p == "--server" && i+1 < len(parts) {
				server = parts[i+1]
			}
		}
		// Reconstruct what the tunnel delivers to HandleC2Command.
		cmdSlice := []string{def.C2CmdDNSQuery, "--token", jobID}
		if queryB64 != "" {
			cmdSlice = append(cmdSlice, "--query", queryB64)
		}
		if server != "" {
			cmdSlice = append(cmdSlice, "--server", server)
		}
		handler.HandleC2Command(&def.MsgTunData{JobID: jobID, CmdSlice: cmdSlice})
		return nil
	}

	port := freeTCPPort(t)
	if err := StartSocks5Proxy(agent.Tag, port, "127.0.0.1"); err != nil {
		t.Fatalf("StartSocks5Proxy: %v", err)
	}
	return port, func() {
		_ = StopSocks5Proxy(port)
		agents.SendCmd = nil
		live.ForgetAgent(agent.UUID)
		_ = agentPipe.Close()
		_ = ccPipe.Close()
		def.CCMsgConn = origCCMsgConn
	}
}

// realTestDNSServer runs an in-process authoritative DNS server on 127.0.0.1
// answering A queries from the given records. Returns its host:port.
func realTestDNSServer(t *testing.T, records map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		if len(r.Question) == 1 {
			q := r.Question[0]
			if ipStr, ok := records[strings.ToLower(q.Name)]; ok && q.Qtype == dns.TypeA {
				if ip := net.ParseIP(ipStr).To4(); ip != nil {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ip,
					})
				}
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String()
}

// dnsRoundTripThroughPivot drives one DNS query through the pivot: it opens a
// UDP-ASSOCIATE, sends the query datagram addressed to dnsHost:dnsPort, and
// returns the raw DNS reply payload the client receives.
func dnsRoundTripThroughPivot(t *testing.T, port int, name string, id uint16, dnsHost string, dnsPort int) []byte {
	t.Helper()
	ctrl, udp := udpAssociate(t, port)
	defer ctrl.Close()
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(20 * time.Second))

	dnssrvIP := net.ParseIP(dnsHost).To4()
	if dnssrvIP == nil {
		t.Fatalf("dns server not an ipv4: %s", dnsHost)
	}
	q := buildDNSQuery(name, id)
	datagram := append([]byte{0, 0, 0, 0x01}, dnssrvIP...)
	datagram = append(datagram, byte(dnsPort>>8), byte(dnsPort&0xff))
	datagram = append(datagram, q...)
	if _, err := udp.Write(datagram); err != nil {
		t.Fatalf("udp write: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatalf("udp read reply: %v", err)
	}
	_, _, start, ok := parseSocks5UDPAddr(buf[:n])
	if !ok {
		t.Fatalf("bad reply datagram: %x", buf[:n])
	}
	reply := buf[start:n]
	if binary.BigEndian.Uint16(reply[0:2]) != id {
		t.Fatalf("reply id 0x%x, want 0x%x", binary.BigEndian.Uint16(reply[0:2]), id)
	}
	return reply
}

// TestSocks5UDPAssociateDNSRealUpstream proves an internal-only name resolves
// through the pivot: the CC forwards the datagram's DST (the DNS server the
// client chose — here our in-process server with only corp.internal) to the
// real agent handler, which forwards the raw query there and returns the
// authoritative answer. The client must receive that exact answer.
func TestSocks5UDPAssociateDNSRealUpstream(t *testing.T) {
	dnsAddr := realTestDNSServer(t, map[string]string{"corp.internal.": "10.77.0.5"})
	dnsHost, dnsPortStr, _ := net.SplitHostPort(dnsAddr)
	var dnsPort int
	_, _ = fmt.Sscanf(dnsPortStr, "%d", &dnsPort)

	// Point the agent-side runtime config at something sane for NotifyC2.
	origTag, origUUID := common.RuntimeConfig.AgentTag, common.RuntimeConfig.AgentUUID
	common.RuntimeConfig.AgentTag = "dns-agent-tag"
	common.RuntimeConfig.AgentUUID = uuid.NewString()
	defer func() {
		common.RuntimeConfig.AgentTag, common.RuntimeConfig.AgentUUID = origTag, origUUID
	}()
	_ = agentutils.GetAgentKey() // ensure a signing key exists for NotifyC2Binary

	port, cleanup := startRealDNSRelayServer(t)
	defer cleanup()

	reply := dnsRoundTripThroughPivot(t, port, "corp.internal", 0x1357, dnsHost, dnsPort)
	if binary.BigEndian.Uint16(reply[6:8]) == 0 {
		t.Fatalf("no answer records in %x", reply)
	}
	if !strings.Contains(string(reply), string([]byte{10, 77, 0, 5})) {
		t.Fatalf("authoritative answer 10.77.0.5 missing: %x", reply)
	}
}

// TestSocks5UDPAssociateDNSRealExternal mirrors the real-world proxy-ns DNS
// use case: resolve a public name (google.com) through a public resolver. It
// skips when the box is offline so the suite stays hermetic.
func TestSocks5UDPAssociateDNSRealExternal(t *testing.T) {
	upstream := "1.1.1.1"
	if ns := firstNameserver(); ns != "" {
		upstream = ns
	}
	if !udpReachable(net.JoinHostPort(upstream, "53")) {
		t.Skipf("no reachable external DNS at %s", upstream)
	}
	upIP := net.ParseIP(upstream).To4()
	if upIP == nil {
		t.Skipf("upstream %s is not an IPv4 literal; skipping external test", upstream)
	}

	origTag, origUUID := common.RuntimeConfig.AgentTag, common.RuntimeConfig.AgentUUID
	common.RuntimeConfig.AgentTag = "dns-agent-tag"
	common.RuntimeConfig.AgentUUID = uuid.NewString()
	defer func() {
		common.RuntimeConfig.AgentTag, common.RuntimeConfig.AgentUUID = origTag, origUUID
	}()
	_ = agentutils.GetAgentKey()

	port, cleanup := startRealDNSRelayServer(t)
	defer cleanup()

	reply := dnsRoundTripThroughPivot(t, port, "google.com", 0x5151, upstream, 53)
	if binary.BigEndian.Uint16(reply[6:8]) == 0 {
		t.Fatalf("google.com via pivot+%s returned no answers: %x", upstream, reply)
	}
}

// buildDNSQuery builds a raw single-question A query for name with the given id.
func buildDNSQuery(name string, id uint16) []byte {
	b := make([]byte, 0, 64)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	b = append(b, hdr...)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, 0x00, 0x01, 0x00, 0x01) // A IN
	return b
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
// effort: no packet round trip required).
func udpReachable(addr string) bool {
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
