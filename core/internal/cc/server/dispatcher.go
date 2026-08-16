package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
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
	if msg == nil {
		return c2RouteContext{}, fmt.Errorf("msg is nil")
	}
	ctx := c2RouteContext{
		AgentUUID: msg.AgentUUID,
		StreamID:  msg.StreamID,
	}
	if len(msg.Capabilities) == 0 {
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
	// Read the first frame (MsgAuth envelope)
	// We use a direct Read from SecureConn instead of a buffered cbor.Decoder
	// to ensure we don't over-read data intended for the service handlers (e.g. FTP data)
	authFrame := make([]byte, 8192) // MsgAuth should definitely fit in 8KB
	n, err := secureConn.Read(authFrame)
	if err != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: first frame read failed from %s: %v", remoteAddr, err)
		return
	}
	var msgAuth def.MsgAuth
	if err := cbor.Unmarshal(authFrame[:n], &msgAuth); err != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: first frame unmarshal failed from %s: %v", remoteAddr, err)
		return
	}
	logging.Debugf("cborProtocolDispatch: decoded MsgAuth from %s: type=%s agent=%s", remoteAddr, msgAuth.Type, msgAuth.AgentUUID)

	if err := transport.VerifyMsgAuth(&msgAuth); err != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: MsgAuth CA verification failed from %s: %v", remoteAddr, err)
		return
	}
	logging.Debugf("cborProtocolDispatch: MsgAuth CA verified from %s", remoteAddr)

	// ── Dispatch by Capabilities ──────────────────────────────────────────────
	routeCtx, routeErr := normalizeRouteFromMsgAuth(&msgAuth)
	if routeErr != nil {
		logging.Errorf("CRITICAL: cborProtocolDispatch: invalid route capabilities for agent %s from %s: %v", strconv.Quote(msgAuth.AgentUUID), remoteAddr, routeErr)
		return
	}
	logging.Debugf("cborProtocolDispatch: normalized route: service=%s agent=%s", routeCtx.Service, strconv.Quote(msgAuth.AgentUUID))

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

	// ── Wait for Check-in ────────────────────────────────────────────────────
	// If the agent is unknown AND the route is NOT Checkin, someone might be
	// enrolling right now. Wait for completion and re-check DB.
	isCheckinRoute := routeCtx.Service == live.RuntimeConfig.C2Routes.Checkin
	if !isKnown && !isCheckinRoute {
		if val, exists := checkinReadyChannels.Load(msgAuth.AgentUUID); exists {
			if ch, ok := val.(chan struct{}); ok {
				logging.Debugf("cborProtocolDispatch: waiting for in-progress enrollment of %s", strconv.Quote(msgAuth.AgentUUID))
				select {
				case <-ch:
					// Re-check DB after signal
					pinnedKey, _, isKnown, err = agents.GetPinnedIdentity(msgAuth.AgentUUID)
					if err != nil {
						logging.Errorf("CRITICAL: cborProtocolDispatch: secondary AgentDB lookup failed for %s: %v", strconv.Quote(msgAuth.AgentUUID), err)
						return
					}
				case <-time.After(15 * time.Second):
					logging.Warningf("cborProtocolDispatch: timed out waiting for enrollment of %s", strconv.Quote(msgAuth.AgentUUID))
				}
			}
		}
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
			msg := fmt.Sprintf("CRITICAL: cborProtocolDispatch: pinned key verification failed for agent %s from %s (sig_ok=%v, err=%v)", strconv.Quote(msgAuth.AgentUUID), remoteAddr, ok, err)
			logging.Errorf("%s", msg)
			return
		}
		logging.Debugf("cborProtocolDispatch: pinned key verified for agent %s", strconv.Quote(msgAuth.AgentUUID))
	} else {
		// Check-in is the only route allowed for unknown agents; all others require prior TOFU enrollment.
		if !isCheckinRoute {
			logging.Errorf("CRITICAL: cborProtocolDispatch: rejecting %s route for unknown agent %s from %s", routeCtx.Service, strconv.Quote(msgAuth.AgentUUID), remoteAddr)
			return
		}
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

	// ── Handshake Complete ───────────────────────────────────────────────────
	// Stop the handshake timer now that we have successfully verified the agent
	// and are about to transition to a potentially persistent service handler.
	timer.Stop()
	logging.Debugf("cborProtocolDispatch: handshake complete, timer stopped for %s", strconv.Quote(msgAuth.AgentUUID))

	// ── Operator presence/idle gate ─────────────────────────────────────────
	// When no operator is online, or the operator has been idle past the
	// configured timeout, the C2 behaves as if it is offline: it refuses all
	// agent connections, including check-in.
	if !operatorOnline() {
		logging.Warningf("cborProtocolDispatch: no operator online, rejecting agent %s from %s", strconv.Quote(msgAuth.AgentUUID), remoteAddr)
		return
	}
	if !operatorIsActive() {
		maybeNotifyOperatorIdle()
		logging.Warningf("cborProtocolDispatch: operator idle, rejecting agent %s from %s", strconv.Quote(msgAuth.AgentUUID), remoteAddr)
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
		dec := cbor.NewDecoder(secureConn)
		enc := cbor.NewEncoder(secureConn)
		if err := handleAgentCheckInStream(dec, enc, &msgAuth, agentUUID, remoteAddr); err != nil {
			logging.Errorf("CRITICAL: cborProtocolDispatch: checkin error for %s: %v", strconv.Quote(agentUUID), err)
		}

	case live.RuntimeConfig.C2Routes.Msg:
		dec := cbor.NewDecoder(secureConn)
		handleMessageTunnelStream(secureConn, dec, remoteAddr, context.Background(), msgAuth.AgentUUID)

	case live.RuntimeConfig.C2Routes.FTP:
		// Provide a cancel function to terminate the connection properly
		ctx, cancel := context.WithCancel(context.Background())
		handleFileUploadStream(secureConn, msgAuth.AgentUUID, routeCtx.StreamID, remoteAddr, ctx, cancel)

	case live.RuntimeConfig.C2Routes.Proxy:
		_, cancel := context.WithCancel(context.Background())
		handleProxyRelayStream(secureConn, msgAuth.AgentUUID, routeCtx.StreamID, remoteAddr, cancel)

	case live.RuntimeConfig.C2Routes.WWW:
		handleWWWRelayStream(secureConn, msgAuth.AgentUUID, routeCtx.StreamID, remoteAddr)

	default:
		logging.Errorf("CRITICAL: cborProtocolDispatch: service %q is disabled or unknown for agent %s from %s", routeCtx.Service, strconv.Quote(msgAuth.AgentUUID), remoteAddr)
	}
}

// cborStreamAccept is the single HTTP handler for agent connections.
func cborStreamAccept(t transport.StreamTransport) {
	remoteAddr := t.RemoteAddrString()
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	if !ipLimiter.getLimiter(ip).Allow() || !globalLimiter.Allow() {
		logging.Warningf("cborStreamAccept: rate limit exceeded for %s, closing connection", remoteAddr)
		_ = t.Close()
		return
	}

	cborProtocolDispatch(t)
}
