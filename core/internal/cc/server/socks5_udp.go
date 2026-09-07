package server

// socks5_udp.go — UDP-ASSOCIATE for the C2-resident SOCKS5 pivot.
//
// SOCKS5 clients (libcurl, Chromium, dig …) that do name resolution through a
// SOCKS5 proxy send UDP DNS datagrams to the proxy via UDP-ASSOCIATE (RFC
// 1928 §7): first they open a TCP control connection with command 0x03, the
// server replies with the address of a UDP relay socket, and the client then
// sends datagrams of the form
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//
// to that relay. Real proxy implementations forward those datagrams to the
// destination; we cannot (the pivot relays byte streams through the agent and
// the agent has no inbound UDP path), so instead we terminate DNS here: a
// datagram whose payload is a DNS query (destination port 53) is handed to the
// bound agent with !dns_query — the agent resolves the name from its own
// position on the network and returns a complete DNS response — and we send
// that response back to the client as a UDP-ASSOCIATE datagram, preserving the
// address the client originally addressed (so its resolver matches the reply).
// All other UDP payloads are dropped: the pivot remains a DNS-only UDP proxy.
//
// The TCP control connection is held open for the whole association (RFC 1928
// requires it) and is watched so the relay UDP socket never leaks.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	// dnsPort is the destination port that marks a UDP-ASSOCIATE datagram as a
	// DNS query. Only these are relayed to the agent.
	dnsPort = 53

	// dnsHeaderSize is the fixed DNS message header length (RFC 1035 §4.1.1).
	dnsHeaderSize = 12

	// socks5UDPIdleCheck is how often the relay loop re-checks the TCP control
	// connection while the UDP socket is idle.
	socks5UDPIdleCheck = 30 * time.Second

	// dnsQueryRelayTimeout bounds one !dns_query round trip.
	dnsQueryRelayTimeout = 15 * time.Second

	// dnsMaxQueryBytes is the largest DNS query we forward to the agent.
	dnsMaxQueryBytes = 4096
	// dnsMaxReplyBytes is the largest DNS reply we accept back from the agent.
	dnsMaxReplyBytes = 64 * 1024
	// dnsMaxConcurrentQueries bounds concurrent agent resolutions per association.
	dnsMaxConcurrentQueries = 4
)

// handleUDPAssociate serves one SOCKS5 UDP-ASSOCIATE request. It blocks until
// the client closes the control connection or the listener is torn down.
func (ls *socks5Listener) handleUDPAssociate(sock net.Conn) error {
	agent := agents.GetAgentByTag(ls.agentTag)
	if agent == nil {
		_ = socks5Reply(sock, socks5RepGeneralFailure, "0.0.0.0", 0)
		return fmt.Errorf("socks5: agent %s is gone", ls.agentTag)
	}

	// The client must send its datagrams to an address it can reach on the
	// same path it used for the TCP control connection. The destination IP of
	// the accepted TCP conn (sock.LocalAddr) is exactly that: it is a local
	// address of this host and it is how the client reached us (loopback for
	// local operators, the WireGuard/VPN IP for remote ones). Bind the relay
	// UDP socket on it and advertise it back as BND.ADDR.
	tcpLocal := sock.LocalAddr()
	reachHost := "127.0.0.1"
	if tcpLocal != nil {
		if h, _, err := net.SplitHostPort(tcpLocal.String()); err == nil && h != "" && !isWildcard(h) {
			reachHost = h
		}
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort(reachHost, "0"))
	if err != nil {
		_ = socks5Reply(sock, socks5RepGeneralFailure, "0.0.0.0", 0)
		return fmt.Errorf("socks5: bind udp relay: %w", err)
	}
	defer pc.Close()

	_, localPortStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	localPort, _ := strconv.Atoi(localPortStr)

	if err := socks5Reply(sock, socks5RepSuccess, reachHost, uint16(localPort)); err != nil {
		return fmt.Errorf("socks5: udp associate reply: %w", err)
	}
	logging.Infof("SOCKS5 UDP-ASSOCIATE from %s -> udp %s:%d via agent %s", sock.RemoteAddr(), reachHost, localPort, ls.agentTag)

	// Watch the TCP control connection: when the client closes it (or the
	// listener is cancelled) the association is over and pc is closed, which
	// unblocks the read loop below.
	controlClosed := make(chan struct{})
	defer close(controlClosed)
	go func() {
		buf := make([]byte, 1)
		_, _ = sock.Read(buf) // blocks until EOF/error
		select {
		case <-controlClosed:
		default:
			_ = pc.Close()
		}
	}()

	buf := make([]byte, 64*1024)

	// Cap concurrent in-flight resolutions per association: an operator-side
	// resolver may burst many queries, but the agent serializes its lookups
	// (see !dns_query), so letting every datagram spawn a goroutine would just
	// pile up waiting jobs. A small pool is enough to keep DNS snappy while
	// bounding memory. On teardown the loop drains dnsWG so no worker outlives
	// the association (workers block on the agent reply up to dnsQueryRelayTimeout).
	workerSem := make(chan struct{}, dnsMaxConcurrentQueries)
	var dnsWG sync.WaitGroup
	defer dnsWG.Wait()
	for {
		_ = pc.SetReadDeadline(time.Now().Add(socks5UDPIdleCheck))
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // idle; the control watcher will close us if the client left
			}
			return nil // socket closed (client gone or listener stopped)
		}
		if n < socks5UDPMinHeader+2 {
			logging.Debugf("socks5 udp: short datagram (%d bytes) from %s", n, clientAddr)
			continue
		}
		relay := buf[:n]
		// RSV(2) must be zero and FRAG must be zero (we never fragment).
		if relay[0] != 0 || relay[1] != 0 || relay[2] != 0 {
			logging.Debugf("socks5 udp: dropping fragmented datagram from %s", clientAddr)
			continue
		}
		dstHost, dstPort, bodyStart, ok := parseSocks5UDPAddr(relay)
		if !ok || dstPort != dnsPort {
			logging.Debugf("socks5 udp: dropping non-DNS datagram (dst %s:%d) from %s", dstHost, dstPort, clientAddr)
			continue
		}
		query := append([]byte(nil), relay[bodyStart:]...)
		if len(query) < dnsHeaderSize || len(query) > dnsMaxQueryBytes {
			logging.Debugf("socks5 udp: dropping malformed DNS query (%d bytes) from %s", len(query), clientAddr)
			continue
		}

		select {
		case workerSem <- struct{}{}:
			dnsWG.Add(1)
			go func(client net.Addr, q []byte) {
				defer dnsWG.Done()
				defer func() { <-workerSem }()
				reply, err := ls.relayDNSQuery(agent, q)
				if err != nil {
					logging.Debugf("socks5 udp: dns relay for %s failed: %v", client, err)
					// Synthesize SERVFAIL so the client fails fast instead of
					// waiting for its own resolver timeout.
					reply = servfailDNSReply(q)
				}
				if len(reply) == 0 {
					return // nothing usable to send
				}
				resp := buildSocks5UDPDatagram(dstHost, dstPort, reply)
				if _, err := pc.WriteTo(resp, client); err != nil {
					logging.Debugf("socks5 udp: write reply to %s: %v", client, err)
				}
			}(clientAddr, query)
		default:
			logging.Debugf("socks5 udp: dropping DNS query from %s (worker pool full)", clientAddr)
		}
	}
}

// relayDNSQuery sends one DNS query to the agent with !dns_query and waits for
// the reply. Success and failure both arrive on the message tunnel as a job
// response with JobID = token: the raw DNS reply (NotifyC2Binary) or a textual
// error (NotifyC2). The tunnel handler caches the payload in live.CmdResults
// and wakes our resultCh (via live.CmdResultsReady), exactly like the CONNECT
// relay path.
func (ls *socks5Listener) relayDNSQuery(agent *def.Emp3r0rAgent, query []byte) ([]byte, error) {
	token := socksProxyTokenPrefix + "dns-" + uuid.NewString()

	live.CmdTime.Store(token, time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"))
	resultCh := make(chan struct{})
	live.CmdResultsReady.Store(token, resultCh)

	cmdLine := fmt.Sprintf("%s --token %s --query %s",
		def.C2CmdDNSQuery, token, base64.StdEncoding.EncodeToString(query))
	if err := agents.SendCmd(cmdLine, token, agent); err != nil {
		clearProxyJobBookkeeping(token)
		return nil, fmt.Errorf("instruct agent: %w", err)
	}

	select {
	case <-resultCh:
		rawAny, ok := live.CmdResults.LoadAndDelete(token)
		clearProxyJobBookkeeping(token)
		if !ok {
			return nil, fmt.Errorf("agent returned no payload")
		}
		raw := []byte(rawAny.(string))
		// The agent answers binary DNS replies on success and "Error: ..."
		// text on malformed input / overload. Only forward a plausible DNS
		// response back to the client: structurally a reply (QR set) echoing
		// the query ID. Anything else is treated as a relay failure so the
		// caller synthesizes SERVFAIL.
		if len(raw) < dnsHeaderSize || len(raw) > dnsMaxReplyBytes {
			return nil, fmt.Errorf("agent resolution failed: %.200s", string(raw))
		}
		if len(query) < 2 || binary.BigEndian.Uint16(raw[0:2]) != binary.BigEndian.Uint16(query[0:2]) ||
			binary.BigEndian.Uint16(raw[2:4])&0x8000 == 0 {
			return nil, fmt.Errorf("agent returned a non-DNS payload: %.200s", string(raw))
		}
		return raw, nil
	case <-time.After(dnsQueryRelayTimeout):
		clearProxyJobBookkeeping(token)
		return nil, fmt.Errorf("agent resolution timed out")
	case <-ls.ctx.Done():
		clearProxyJobBookkeeping(token)
		return nil, fmt.Errorf("listener stopped")
	}
}

// parseSocks5UDPAddr parses the variable address part of a UDP-ASSOCIATE
// datagram: ATYP DST.ADDR DST.PORT. Returns host, port and the byte offset of
// the payload that follows it. All indices are bounds-checked.
func parseSocks5UDPAddr(b []byte) (host string, port uint16, bodyStart int, ok bool) {
	if len(b) < socks5UDPMinHeader+2 {
		return "", 0, 0, false
	}
	atyp := b[3]
	pos := 4
	switch atyp {
	case socks5AtypIPv4:
		if pos+4+2 > len(b) {
			return "", 0, 0, false
		}
		host = net.IP(b[pos : pos+4]).String()
		pos += 4
	case socks5AtypIPv6:
		if pos+16+2 > len(b) {
			return "", 0, 0, false
		}
		host = net.IP(b[pos : pos+16]).String()
		pos += 16
	case socks5AtypDomain:
		if pos+1 > len(b) {
			return "", 0, 0, false
		}
		l := int(b[pos])
		pos++
		if l == 0 || pos+l+2 > len(b) {
			return "", 0, 0, false
		}
		host = string(b[pos : pos+l])
		pos += l
	default:
		return "", 0, 0, false
	}
	port = binary.BigEndian.Uint16(b[pos : pos+2])
	return host, port, pos + 2, true
}

// buildSocks5UDPDatagram wraps a DNS reply payload into a UDP-ASSOCIATE
// datagram addressed to host:port (the original DST of the query).
func buildSocks5UDPDatagram(host string, port uint16, payload []byte) []byte {
	atyp := socks5AtypIPv4
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		atyp = socks5AtypIPv6
	}
	addr := socks5Addr(host, port, atyp)
	out := make([]byte, 0, 4+len(addr)+len(payload))
	out = append(out, 0x00, 0x00, 0x00, atyp) // RSV(2)=0 FRAG=0
	out = append(out, addr...)
	out = append(out, payload...)
	return out
}

// servfailDNSReply synthesizes a SERVFAIL response for a query we could not
// relay. It echoes the query ID and question section so the client can match
// it, and marks QR/RA with rcode 2. q must be a well-formed single-question
// query (we already validated that before relaying).
func servfailDNSReply(q []byte) []byte {
	if len(q) < dnsHeaderSize {
		return nil
	}
	// Locate the question section (up to QTYPE/QCLASS after the name) so we can
	// echo it. QDCOUNT is 1 only when the name parses.
	qend := 0
	pos := dnsHeaderSize
	for pos < len(q) {
		l := int(q[pos])
		if l == 0 {
			pos++
			if pos+4 <= len(q) {
				qend = pos + 4
			}
			break
		}
		if l > 63 || pos+1+l >= len(q) {
			break
		}
		pos += 1 + l
	}

	reply := make([]byte, 0, dnsHeaderSize+(qend-dnsHeaderSize))
	reply = append(reply, q[:2]...) // ID
	reqFlags := binary.BigEndian.Uint16(q[2:4])
	flags := uint16(0x8000 | 0x0080 | (reqFlags & 0x0100) | 0x0002) // SERVFAIL
	reply = binary.BigEndian.AppendUint16(reply, flags)
	if qend > 0 {
		reply = append(reply, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // QD=1, AN/NS/AR=0
		reply = append(reply, q[dnsHeaderSize:qend]...)
	} else {
		reply = append(reply, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	}
	return reply
}

func isWildcard(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::" || host == "[::]"
}
