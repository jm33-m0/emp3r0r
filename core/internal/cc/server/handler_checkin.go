package server

import (
	"encoding/base64"
	"errors"
	"fmt"
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

// rotationRateLimiter tracks key rotation timestamps per AgentUUID to prevent log flooding
var rotationRateLimiter sync.Map

// handleAgentCheckInStream is the protocol-native checkin handler.
// It is transport-agnostic and only depends on an encrypted byte stream.
// secureConn is already authenticated and its first frame (MsgAuth) consumed by dec.
func handleAgentCheckInStream(dec *cbor.Decoder, auth *def.MsgAuth, agentUUID, remoteAddr string) error {
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
		logging.Errorf("CRITICAL: handleAgentCheckIn: compatibility route/body UUID mismatch: body=%s route=%s", strconv.Quote(target.UUID), strconv.Quote(agentUUID))
	}

	// ── Rate limiting: cap ALL log/alert output per UUID ─────────────────────
	// Must run immediately after we have a validated UUID so that every
	// subsequent rejection path (missing key, key mismatch, ghost session, etc.)
	// is capped. An attacker with a valid CA cert cannot flood logs or the
	// operator console beyond 10 requests/minute per agent UUID.
	{
		now := time.Now()
		validTimestamps := []time.Time{}
		if val, exists := rotationRateLimiter.Load(target.UUID); exists {
			for _, t := range val.([]time.Time) {
				if now.Sub(t) < time.Minute {
					validTimestamps = append(validTimestamps, t)
				}
			}
		}
		validTimestamps = append(validTimestamps, now)
		rotationRateLimiter.Store(target.UUID, validTimestamps)
		if len(validTimestamps) > 10 {
			// Silent drop — no log, no broadcast.
			return fmt.Errorf("forbidden: rate limit")
		}
	}

	// SECURITY: Agent MUST provide its public key in every checkin.
	if target.PublicKey == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: Agent %s provided no public key, rejecting", strconv.Quote(target.UUID))
		return fmt.Errorf("unauthorized: missing public key")
	}
	if target.UUIDSig == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: Agent %s provided no UUID signature, rejecting", strconv.Quote(target.UUID))
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
		logging.Errorf("CRITICAL: handleAgentCheckIn: AgentDB lookup failed for %s: %v", strconv.Quote(target.UUID), err)
		return fmt.Errorf("forbidden: trust lookup failed")
	}

	// ── Phase 2: TOFU Verification (DB-Authoritative) ─────────────────────
	if isKnown && pinnedKey == "" {
		logging.Errorf("CRITICAL: handleAgentCheckIn: %s has empty pinned key in DB", strconv.Quote(target.UUID))
		return fmt.Errorf("forbidden: invalid pinned identity")
	}

	if isKnown && target.PublicKey != pinnedKey {
		ips := strings.Join(target.IPs, ", ")
		msg := fmt.Sprintf("SECURITY: agent %s presented a different key — rejecting (key rotation is disabled).\n"+
			"  Rejected Payload Info:\n    User: %s\n    Host: %s\n    IPs:  %s\n    OS:   %s\n"+
			"  If this is a legitimate reinstall, run `forget_agent %s` to reset its identity.",
			target.UUID, target.User, target.Hostname, ips, target.OS, strconv.Quote(target.UUID))
		logging.Errorf("%s", msg)
		operatorBroadcastPrintf(logging.FATAL, "%s", msg)
		return fmt.Errorf("forbidden: key rotation")
	}
	if isKnown && pinnedUUIDSig != "" && target.UUIDSig != pinnedUUIDSig {
		msg := fmt.Sprintf("SECURITY: agent %s presented mismatching UUID signature — rejecting clone/impersonation risk", target.UUID)
		logging.Errorf("%s", msg)
		operatorBroadcastPrintf(logging.FATAL, "%s", msg)
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
	if isKnown {
		target.PublicKey = pinnedKey
		if pinnedUUIDSig != "" {
			target.UUIDSig = pinnedUUIDSig
		}
	}

	// ── Phase 3: Session Admission (Explicit Duplicate Prohibition) ────────
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
	if sessionErr := agents.StartSession(target.UUID, sessionID, remoteAddr); sessionErr != nil {
		if errors.Is(sessionErr, agents.ErrSessionAlreadyActive) {
			logging.Errorf("CRITICAL: handleAgentCheckIn: duplicate live session blocked for %s from %s", strconv.Quote(target.UUID), remoteAddr)
			return fmt.Errorf("forbidden: duplicate session")
		}
		logging.Errorf("CRITICAL: handleAgentCheckIn: session admission failed for %s: %v", strconv.Quote(target.UUID), sessionErr)
		return fmt.Errorf("forbidden: session admission failed")
	}

	// ── Phase 4: Runtime Projection Update (Non-Security State) ────────────
	var (
		existingCtrl *live.AgentControl
		placeholder  any // the key (agent pointer) currently in the map
	)
	if _, ctrl, key, found := agents.RuntimeControlByUUID(target.UUID); found {
		existingCtrl = ctrl
		placeholder = key
	}

	if placeholder != nil {
		// Replace placeholder/old entry with the new authoritative data
		live.AgentControlMap.Delete(placeholder)
	}

	if existingCtrl == nil {
		existingCtrl = &live.AgentControl{Index: agents.AssignAgentIndex()}
	}
	live.AgentControlMap.Store(target, existingCtrl)

	logging.Infof("Updated agent %q with full data from CBOR", target.UUID)

	// Signal that public key is now available (for any waiting requests)
	closeCheckinReadyChannel(target.UUID)
	logging.Debugf("Signaled checkin completion for %s", strconv.Quote(target.UUID))

	// Now that agent is in memory with pubkey, safe to proceed with other operations
	// (message tunnel requests can now resolve the pubkey)

	// ------------------------------------------------------------ // SECURITY: Clone Detection & Session Management
	if agents.AgentDB != nil {
		if err := agents.RecordAgentCheckin(target); err != nil {
			_ = agents.EndSession(target.UUID)
			logging.Errorf("CRITICAL: Failed to record agent check-in (session rolled back): %v", err)
			return fmt.Errorf("forbidden: failed to persist check-in")
		}
	}

	shortname := strings.Split(target.Tag, "-agent")[0]
	if util.IsExist(agents.AgentsJSON) {
		if l := agents.RefreshAgentLabel(target); l != "" {
			shortname = l
		}
	}

	if placeholder == nil {
		logging.Infof("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
	} else {
		if logging.Level >= 4 {
			logging.Debugf("Agent reconnected: %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}

	return nil
}
