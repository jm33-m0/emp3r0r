package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// rotationRateLimiter tracks key rotation timestamps per AgentUUID to prevent log flooding
var rotationRateLimiter sync.Map

// checkinRateLimitWindow is the maximum number of rate-limited events allowed per
// agent UUID in a one-minute window.
const checkinRateLimitWindow = 10

// rotationLimiterLastPurge throttles the stale-entry sweep so the map can never
// grow without bound and the sweep stays O(n) at most once a minute.
var rotationLimiterLastPurge atomic.Int64

// purgeStaleRotationEntries drops per-UUID timestamps that have fallen outside
// the one-minute window. Without it a hostile agent could enrol endless random
// UUIDs and leak one rate-limiter entry each, forever.
func purgeStaleRotationEntries(now time.Time) {
	last := rotationLimiterLastPurge.Load()
	if now.Unix()-last < 60 {
		return
	}
	if !rotationLimiterLastPurge.CompareAndSwap(last, now.Unix()) {
		return
	}
	rotationRateLimiter.Range(func(k, v any) bool {
		times, ok := v.([]time.Time)
		if !ok || len(times) == 0 || now.Sub(times[len(times)-1]) > time.Minute {
			rotationRateLimiter.Delete(k)
		}
		return true
	})
}

// recordCheckinAttempt records one check-in attempt for uuid and reports whether
// it is within the per-UUID rate limit. The stored slice is capped at just past
// the window so a flood against one UUID cannot grow server memory without
// bound.
func recordCheckinAttempt(uuid string, now time.Time) bool {
	validTimestamps := make([]time.Time, 0, checkinRateLimitWindow+1)
	if val, exists := rotationRateLimiter.Load(uuid); exists {
		if stored, ok := val.([]time.Time); ok {
			for _, ts := range stored {
				if now.Sub(ts) < time.Minute {
					validTimestamps = append(validTimestamps, ts)
				}
			}
		}
	}
	validTimestamps = append(validTimestamps, now)
	if len(validTimestamps) > checkinRateLimitWindow+1 {
		validTimestamps = validTimestamps[len(validTimestamps)-(checkinRateLimitWindow+1):]
	}
	rotationRateLimiter.Store(uuid, validTimestamps)
	purgeStaleRotationEntries(now)
	return len(validTimestamps) <= checkinRateLimitWindow
}

// handleAgentCheckInStream is the protocol-native checkin handler.
// It is transport-agnostic and only depends on an encrypted byte stream.
// secureConn is already authenticated and its first frame (MsgAuth) consumed by dec.
func handleAgentCheckInStream(dec *cbor.Decoder, out *cbor.Encoder, auth *def.MsgAuth, agentUUID, remoteAddr string) error {
	target := new(def.Emp3r0rAgent)
	// Dispatcher already decoded the first MsgAuth frame using dec.
	// We are now at the second frame, which MUST be the Emp3r0rAgent info.
	err := dec.Decode(target)
	if err != nil {
		logging.Errorf("CRITICAL: handleAgentCheckIn decode agent payload error from %s: %v", remoteAddr, err)
		return err
	}

	// SECURITY: Treat agent-supplied metadata as hostile.
	util.SanitizeAgentMetadata(target)

	if target.UUID == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: empty UUID in payload")
		return fmt.Errorf("forbidden: empty uuid")
	}
	if agentUUID != "" && target.UUID != agentUUID {
		logging.Errorf("CRITICAL: handleAgentCheckIn: route/body UUID mismatch: body=%s route=%s", util.AgentRef(target.UUID), util.AgentRef(agentUUID))
		return fmt.Errorf("forbidden: uuid mismatch")
	}

	// The operator-facing identifier is derived exclusively from the verified
	// UUID. Overwrite whatever the agent reported so a hostile agent can never
	// inject content (tmux format syntax, control bytes, ...) into any surface
	// that renders the identifier.
	target.Tag = util.GenAgentTag(target.UUID)

	// ── Rate limiting: cap ALL log/alert output per UUID ─────────────────────
	// Must run immediately after we have a validated UUID so that every
	// subsequent rejection path (missing key, key mismatch, ghost session, etc.)
	// is capped. An attacker with a valid CA cert cannot flood logs or the
	// operator console beyond 10 requests/minute per agent UUID.
	if !recordCheckinAttempt(target.UUID, time.Now()) {
		// Silent drop — no log, no broadcast.
		return fmt.Errorf("forbidden: rate limit")
	}

	// SECURITY: Agent MUST provide its public key in every checkin.
	if target.PublicKey == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: Agent %s provided no public key, rejecting", util.AgentRef(target.UUID))
		return fmt.Errorf("unauthorized: missing public key")
	}
	if target.UUIDSig == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: Agent %s provided no UUID signature, rejecting", util.AgentRef(target.UUID))
		return fmt.Errorf("unauthorized: missing uuid signature")
	}
	if agents.AgentDB == nil {
		logging.Errorf("CRITICAL: handleAgentCheckIn: AgentDB unavailable for trust decision")
		return fmt.Errorf("forbidden: trust store unavailable")
	}

	// ── Phase 1: Identity & State Lookup ───────────────────────────────────
	var (
		isKnown       bool
		pinnedKey     string
		pinnedUUIDSig string
	)
	pinnedKey, pinnedUUIDSig, isKnown, err = agents.GetPinnedIdentity(target.UUID)
	if err != nil {
		logging.Errorf("CRITICAL: handleAgentCheckIn: AgentDB lookup failed for %s: %v", util.AgentRef(target.UUID), err)
		return fmt.Errorf("forbidden: trust lookup failed")
	}

	// ── Phase 2: TOFU Verification (DB-Authoritative) ─────────────────────
	if isKnown && pinnedKey == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: %s has empty pinned key in DB", util.AgentRef(target.UUID))
		return fmt.Errorf("forbidden: invalid pinned identity")
	}

	if isKnown && target.PublicKey != pinnedKey {
		ips := strings.Join(target.IPs, ", ")
		msg := fmt.Sprintf("SECURITY: agent %s presented a different key — rejecting (key rotation is disabled).\n"+
			"  Rejected Payload Info:\n    User: %s\n    Host: %s\n    IPs:  %s\n    OS:   %s\n"+
			"  If this is a legitimate reinstall, run `forget_agent %s` to reset its identity.",
			util.AgentRef(target.UUID), target.User, target.Hostname, ips, target.OS, util.GenAgentTag(target.UUID))
		logging.Errorf("%s", msg)
		logging.Notify(logging.ERROR, "%s", msg)
		return fmt.Errorf("forbidden: key rotation")
	}
	if isKnown && pinnedUUIDSig != "" && target.UUIDSig != pinnedUUIDSig {
		msg := fmt.Sprintf("SECURITY: agent %s presented mismatching UUID signature — rejecting clone/impersonation risk", util.AgentRef(target.UUID))
		logging.Errorf("%s", msg)
		logging.Notify(logging.ERROR, "%s", msg)
		return fmt.Errorf("forbidden: identity token mismatch")
	}

	if !isKnown {
		if auth == nil {
			return fmt.Errorf("forbidden: missing auth envelope context")
		}
		if auth.AgentUUID != target.UUID {
			return fmt.Errorf("forbidden: auth/payload UUID mismatch")
		}
		if auth.AgentProof == "" {
			return fmt.Errorf("forbidden: missing agent proof for first enrollment")
		}
		proof, decodeErr := base64.URLEncoding.DecodeString(auth.AgentProof)
		if decodeErr != nil {
			return fmt.Errorf("forbidden: bad agent proof encoding: %w", decodeErr)
		}
		canonical := transport.CanonicalAuthString(auth.AgentUUID, auth.Timestamp, auth.Nonce, auth.Capabilities)
		ok, verifyErr := transport.VerifySignatureWithPEM([]byte(target.PublicKey), []byte(canonical), proof)
		if verifyErr != nil || !ok {
			return fmt.Errorf("forbidden: first enrollment proof invalid")
		}
	}

	target.From = remoteAddr
	target.LastSeen = time.Now()
	agents.MarkAgentSeen(target, target.LastSeen)
	if isKnown {
		target.PublicKey = pinnedKey
		if pinnedUUIDSig != "" {
			target.UUIDSig = pinnedUUIDSig
		}
	}

	// ── Phase 2.5: Synchronous Persistence (Identity Enrollment) ────────
	// SECURITY: identity MUST be persistent BEFORE session admission or signals.
	// This ensures TOFU is locked and any concurrent dispatcher threads can
	// find the agent in the database.
	if agents.AgentDB != nil {
		if err := agents.RecordAgentCheckin(target); err != nil {
			logging.Errorf("CRITICAL: Failed to record agent enrollment for %s: %v", util.AgentRef(target.UUID), err)
			return fmt.Errorf("forbidden: failed to persist identity")
		}
	}

	// ── Phase 3: Session Admission (Explicit Duplicate Prohibition) ────────
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	if sessionErr := agents.StartSession(target.UUID, sessionID, remoteAddr); sessionErr != nil {
		if errors.Is(sessionErr, agents.ErrSessionAlreadyActive) {
			logging.Notify(logging.ERROR, "CRITICAL: handleAgentCheckIn: duplicate live session blocked for %s from %s", util.AgentRef(target.UUID), remoteAddr)
			return fmt.Errorf("forbidden: duplicate session")
		}
		logging.Errorf("CRITICAL: handleAgentCheckIn: session admission failed for %s: %v", util.AgentRef(target.UUID), sessionErr)
		return fmt.Errorf("forbidden: session admission failed")
	}

	// ── Phase 4: Runtime Projection Update (Non-Security State) ────────────
	// Upsert the registry entry by UUID. A re-check-in keeps the existing live
	// tunnel instead of resetting it.
	existing, alreadyKnown := live.LookupAgent(target.UUID)
	rec := &live.AgentRecord{Agent: target}
	if alreadyKnown {
		rec.Control = existing.Control
	}
	if rec.Control == nil {
		rec.Control = &live.AgentControl{Index: agents.AssignAgentIndex()}
	}
	live.PublishAgent(rec)

	logging.Infof("Updated agent %s with full data from CBOR", util.AgentRef(target.UUID))

	// Signal that public key is now available (for any waiting requests)
	// ONLY after DB persistence and Session admission are complete.
	closeCheckinReadyChannel(target.UUID)
	logging.Debugf("Signaled checkin completion for %s", util.AgentRef(target.UUID))

	// Now that agent is persistent and in memory, safe to proceed with other operations
	shortname := target.Tag

	if !alreadyKnown {
		logging.Notify(logging.INFO, "Checked in: %s from %s, running %s", util.AgentRef(target.UUID), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
	} else {
		if logging.Level >= 4 {
			logging.Debugf("Agent reconnected: %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}

	// Send checkin-ok ACK to agent
	// This helps agents synchronize their connection teardown, especially in polling modes
	ack := &def.MsgTunData{Tag: "checkin-ok"}
	if err := out.Encode(ack); err != nil {
		logging.Errorf("Failed to send checkin-ok ACK to %s: %v", util.AgentRef(target.UUID), err)
	}

	return nil
}
