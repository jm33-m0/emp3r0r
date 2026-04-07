package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// replayNonceCache prevents MsgAuth replay attacks
	replayNonceCache sync.Map
	// checkinReadyChannels tracks agents waiting for their first checkin to finish
	checkinReadyChannels sync.Map
)

// C2 Route Names are now shared via the def package:
// def.C2RouteCheckin, def.C2RouteMsg, def.C2RouteFTP, def.C2RouteWWW, def.C2RouteProxy

type c2RouteContext struct {
	Service   string
	AgentUUID string
	StreamID  string
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// closeCheckinReadyChannel signals that an agent's first check-in is complete
func closeCheckinReadyChannel(agentUUID string) {
	if val, ok := checkinReadyChannels.Load(agentUUID); ok {
		if ch, ok := val.(chan struct{}); ok {
			close(ch)
		}
		checkinReadyChannels.Delete(agentUUID)
	}
}

// normalizeRouteFromMsgAuth interprets MsgAuth capabilities as routing information.
// Exactly one configured route capability must be provided; no default/fallback route is allowed.
func normalizeRouteFromMsgAuth(msg *def.MsgAuth) (c2RouteContext, error) {
	ctx := c2RouteContext{
		AgentUUID: msg.AgentUUID,
		StreamID:  msg.StreamID,
	}
	if msg == nil || len(msg.Capabilities) == 0 {
		return ctx, fmt.Errorf("missing route capability")
	}

	allowed := map[string]struct{}{
		live.RuntimeConfig.C2Routes.Checkin: {},
		live.RuntimeConfig.C2Routes.Msg:     {},
		live.RuntimeConfig.C2Routes.FTP:     {},
		live.RuntimeConfig.C2Routes.WWW:     {},
		live.RuntimeConfig.C2Routes.Proxy:   {},
	}

	seen := ""
	for _, cap := range msg.Capabilities {
		c := strings.ToLower(strings.TrimSpace(cap))
		if _, ok := allowed[c]; !ok {
			continue
		}
		if seen != "" && seen != c {
			return ctx, fmt.Errorf("multiple route capabilities are not allowed")
		}
		seen = c
	}
	if seen == "" {
		return ctx, fmt.Errorf("no configured route capability provided")
	}
	ctx.Service = seen
	return ctx, nil
}

// cborProtocolDispatch is the entry point for the pure-CBOR C2 protocol.
// It performs initial auth, protects against replays, and routes the stream
// to the appropriate persistent or one-shot handler.
func cborProtocolDispatch(t transport.StreamTransport) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("cborProtocolDispatch panic: %v\n%s", r, util.CallStack())
		}
	}()

	// ── Step ①: CA verification ──────────────────────────────────────────────
	// The very first CBOR frame MUST be a MsgAuth envelope.
	// All C2 comms are PSK-encrypted from the start.
	// Set a timeout for the initial handshake to prevent deadlocks.
	timer := time.AfterFunc(10*time.Second, func() {
		_ = t.Close()
	})
	defer timer.Stop()

	secureConn := transport.NewSecureConn(t)
	defer t.Close() // Ensure connection is closed when dispatch or persistent handler returns

	remoteAddr := t.RemoteAddrString()
	dec := cbor.NewDecoder(secureConn)
	var msgAuth def.MsgAuth
	if err := dec.Decode(&msgAuth); err != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: first frame decode failed from %s: %v", remoteAddr, err)
		return
	}
	logging.Debugf("cborProtocolDispatch: decoded MsgAuth from %s: type=%d agent=%s", remoteAddr, msgAuth.Type, msgAuth.AgentUUID)

	if err := transport.VerifyMsgAuth(&msgAuth); err != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: MsgAuth CA verification failed from %s: %v", remoteAddr, err)
		return
	}
	logging.Debugf("cborProtocolDispatch: MsgAuth CA verified from %s", remoteAddr)

	// ── Step ①.⑤: Pinned Key (TOFU) Verification ────────────────────────────
	// Security decisions are DB-authoritative. Memory maps are runtime projections only.
	if agents.AgentDB == nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: AgentDB unavailable for trust decision from %s", remoteAddr)
		return
	}
	pinnedKey, _, isKnown, err := agents.GetPinnedIdentity(msgAuth.AgentUUID)
	if err != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: AgentDB lookup failed for %s from %s: %v", strconv.Quote(msgAuth.AgentUUID), remoteAddr, err)
		return
	}

	if isKnown {
		if pinnedKey == "" {
			logging.Errorf("CRITICAL: cborProtocolDispatch: agent %s has empty pinned key in DB", strconv.Quote(msgAuth.AgentUUID))
			return
		}
		if msgAuth.AgentProof == "" {
			logging.Errorf("CRITICAL: cborProtocolDispatch: agent %s is known but provided no AgentProof from %s", strconv.Quote(msgAuth.AgentUUID), remoteAddr)
			return
		}
		proof, err := base64.URLEncoding.DecodeString(msgAuth.AgentProof)
		if err != nil {
			logging.Errorf("CRITICAL: cborProtocolDispatch: decode agent proof failed for %s from %s: %v", strconv.Quote(msgAuth.AgentUUID), remoteAddr, err)
			return
		}
		canonical := transport.CanonicalAuthString(msgAuth.AgentUUID, msgAuth.Timestamp, msgAuth.Nonce, msgAuth.Capabilities)
		ok, err := transport.VerifySignatureWithPEM([]byte(pinnedKey), []byte(canonical), proof)
		if err != nil || !ok {
			logging.Errorf("CRITICAL: cborProtocolDispatch: pinned key verification failed for agent %s from %s (ok=%v, err=%v)", strconv.Quote(msgAuth.AgentUUID), remoteAddr, ok, err)
			return
		}
		logging.Debugf("cborProtocolDispatch: pinned key verified for agent %s", strconv.Quote(msgAuth.AgentUUID))
	} else {
		logging.Debugf("cborProtocolDispatch: agent %s has no pinned identity in DB (first enrollment path)", strconv.Quote(msgAuth.AgentUUID))
	}

	// ── Step ②: Replay protection ────────────────────────────────────────────
	now := time.Now().Unix()
	nonceKey := msgAuth.AgentUUID + ":" + msgAuth.Nonce
	if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
		if prevTS, ok := prev.(int64); ok && abs64(now-prevTS) <= transport.ReplayWindowSeconds {
			logging.Errorf("CRITICAL: cborProtocolDispatch: replay detected for agent %s from %s", strconv.Quote(msgAuth.AgentUUID), remoteAddr)
			return
		}
	}
	replayNonceCache.Store(nonceKey, msgAuth.Timestamp)
	// purge stale entries
	replayNonceCache.Range(func(k, v any) bool {
		if cachedTS, ok := v.(int64); ok && abs64(now-cachedTS) > transport.ReplayWindowSeconds {
			replayNonceCache.Delete(k)
		}
		return true
	})

	// ── Dispatch by Capabilities ──────────────────────────────────────────────
	routeCtx, routeErr := normalizeRouteFromMsgAuth(&msgAuth)
	if routeErr != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: invalid route capabilities for agent %s from %s: %v", strconv.Quote(msgAuth.AgentUUID), remoteAddr, routeErr)
		return
	}
	logging.Infof("cborProtocolDispatch: service=%s agent=%s from %s", routeCtx.Service, strconv.Quote(msgAuth.AgentUUID), remoteAddr)

	// Check-in is the only route allowed for unknown agents; all others require prior TOFU enrollment.
	isCheckinRoute := routeCtx.Service == live.RuntimeConfig.C2Routes.Checkin
	if !isKnown && !isCheckinRoute {
		logging.Errorf("CRITICAL: cborProtocolDispatch: rejecting %s route for unknown agent %s from %s", routeCtx.Service, strconv.Quote(msgAuth.AgentUUID), remoteAddr)
		return
	}

	switch routeCtx.Service {
	case live.RuntimeConfig.C2Routes.Checkin:
		agentUUID := msgAuth.AgentUUID
		if agentUUID != "" {
			defer closeCheckinReadyChannel(agentUUID)
			readyChan := make(chan struct{})
			checkinReadyChannels.Store(agentUUID, readyChan)
		}
		if err := handleAgentCheckInStream(dec, &msgAuth, agentUUID, remoteAddr); err != nil {
			logging.Errorf("CRITICAL: cborProtocolDispatch: checkin error for %s: %v", strconv.Quote(agentUUID), err)
		}

	case live.RuntimeConfig.C2Routes.Msg:
		handleMessageTunnelStream(secureConn, dec, remoteAddr, context.Background())

	case live.RuntimeConfig.C2Routes.FTP:
		// Provide a cancel function to terminate the connection properly
		ctx, cancel := context.WithCancel(context.Background())
		handleFileUploadStream(secureConn, msgAuth.AgentUUID, routeCtx.StreamID, remoteAddr, ctx, cancel)

	case live.RuntimeConfig.C2Routes.Proxy:
		_, cancel := context.WithCancel(context.Background())
		network.HandlePortFwdStream(&network.StreamHandler{}, secureConn, msgAuth.AgentUUID, routeCtx.StreamID, remoteAddr, cancel)

	case live.RuntimeConfig.C2Routes.WWW:
		handleFileDownloadStream(msgAuth.AgentUUID, secureConn, routeCtx.StreamID, remoteAddr)

	default:
		logging.Errorf("CRITICAL: cborProtocolDispatch: service %q is disabled or unknown for agent %s from %s", routeCtx.Service, strconv.Quote(msgAuth.AgentUUID), remoteAddr)
	}
}

// cborStreamAccept is the single HTTP handler for agent connections.
func cborStreamAccept(t transport.StreamTransport) {
	cborProtocolDispatch(t)
}

// handleFileDownloadStream serves files from the WWW directory to agents.
func handleFileDownloadStream(agentUUID string, conn io.ReadWriteCloser, filename string, remoteAddr string) {
	if agentUUID == "" {
		logging.Errorf("handleFileDownloadStream: blocked download stream from %s with empty agentUUID", remoteAddr)
		conn.Close()
		return
	}
	if strings.TrimSpace(filename) == "" {
		logging.Errorf("handleFileDownloadStream: blocked download stream from %s with empty filename", remoteAddr)
		conn.Close()
		return
	}

	// SECURITY: Verify that agent is enrolled and has an active session.
	// Auxiliary routes (FTP, Proxy, WWW) are sub-operations of the main agent session.
	if agents.AgentDB == nil {
		logging.Errorf("handleFileDownloadStream: AgentDB unavailable for %s from %s", strconv.Quote(agentUUID), remoteAddr)
		conn.Close()
		return
	}
	pinnedKey, _, found, lookupErr := agents.GetPinnedIdentity(agentUUID)
	if lookupErr != nil {
		logging.Errorf("CRITICAL: handleFileDownloadStream: AgentDB lookup failed for %s from %s: %v", strconv.Quote(agentUUID), remoteAddr, lookupErr)
		conn.Close()
		return
	}
	if !found || pinnedKey == "" {
		logging.Errorf("CRITICAL: handleFileDownloadStream: agent %s not enrolled or has empty pinned key from %s", strconv.Quote(agentUUID), remoteAddr)
		conn.Close()
		return
	}

	// Clean up on exit
	defer conn.Close()

	// Update heartbeat to show activity on this auxiliary channel
	_ = agents.UpdateSessionHeartbeat(agentUUID)

	// SECURITY: Ensure the filename is just a basename to prevent path traversal
	filename = filepath.Base(filename)
	path := live.Temp + transport.WWW + filename
	if st, statErr := os.Stat(path); statErr != nil {
		logging.Warningf("handleFileDownloadStream: stat %s failed: %v", path, statErr)
		return
	} else if !st.Mode().IsRegular() {
		logging.Warningf("handleFileDownloadStream: refusing non-regular file %s", path)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		logging.Warningf("handleFileDownloadStream: open %s failed: %v", path, err)
		return
	}
	defer f.Close()

	n, err := io.Copy(conn, f)
	if err != nil {
		logging.Errorf("handleFileDownloadStream: served %s to %s failed: %v", filename, remoteAddr, err)
		return
	}
	logging.Infof("handleFileDownloadStream: served %s (%d bytes) to %s", filename, n, remoteAddr)
}
