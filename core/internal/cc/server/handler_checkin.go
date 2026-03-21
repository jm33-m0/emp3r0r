package server

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// rotationRateLimiter tracks key rotation timestamps per AgentUUID to prevent log flooding
var rotationRateLimiter sync.Map

// handleAgentCheckInStream is the protocol-native checkin handler.
// It is transport-agnostic and only depends on an encrypted byte stream.
// secureConn is already authenticated and its first frame (MsgAuth) consumed by dec.
func handleAgentCheckInStream(dec *cbor.Decoder, agentUUID, remoteAddr string) error {
	target := new(def.Emp3r0rAgent)
	// Dispatcher already decoded the first MsgAuth frame using dec.
	// We are now at the second frame, which MUST be the Emp3r0rAgent info.
	err := dec.Decode(target)
	if err != nil {
		logging.Warningf("handleAgentCheckIn decode agent payload error from %s: %v", remoteAddr, err)
		return err
	}

	// SECURITY: Treat agent-supplied metadata as hostile.
	util.SanitizeAgentMetadata(target)

	if target.UUID == "" {
		logging.Warningf("handleAgentCheckIn: empty UUID in payload")
		return fmt.Errorf("forbidden: empty uuid")
	}
	if agentUUID != "" && target.UUID != agentUUID {
		logging.Warningf("handleAgentCheckIn: compatibility route/body UUID mismatch: body=%s route=%s", strconv.Quote(target.UUID), strconv.Quote(agentUUID))
	}

	// Check duplicate sessions by payload identity (authoritative source).
	if agents.IsAgentExistByUUID(target.UUID) {
		agent := agents.GetAgentByUUID(target.UUID)
		if agent != nil {
			if val, ok := live.AgentControlMap.Load(agent); ok {
				ctrl := val.(*live.AgentControl)
				if ctrl.Conn != nil {
					if agentUUID == "" || target.UUID != agentUUID {
						logging.Warningf("handleAgentCheckIn: %s already connected, refusing duplicated checkin", target.UUID)
					}
					return fmt.Errorf("forbidden: duplicated checkin")
				}
			}
		}
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
		logging.Warningf("handleAgentCheckIn: Agent %s provided no public key, rejecting", strconv.Quote(target.UUID))
		return fmt.Errorf("unauthorized: missing public key")
	}

	// ── Phase 1: Identity & State Lookup ───────────────────────────────────
	var (
		existingCtrl *live.AgentControl
		existingKey  string
		isConnected  bool
		placeholder  any // the key (agent pointer) currently in the map
	)
	live.AgentControlMap.Range(func(key, value any) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == target.UUID {
			ctrl := value.(*live.AgentControl)
			existingCtrl = ctrl
			existingKey = a.PublicKey
			placeholder = key
			if ctrl.Conn != nil {
				isConnected = true
			}
			return false
		}
		return true
	})

	// If not in map, check persistence
	if placeholder == nil {
		if agents.AgentDB != nil {
			stored, err := agents.GetStoredAgent(target.UUID)
			if err == nil && stored != nil {
				existingKey = stored.PublicKey
			}
		}
	}

	// ── Phase 2: Duplicate Protection ──────────────────────────────────────
	if isConnected {
		logging.Warningf("handleAgentCheckIn: %s already connected, refusing duplicated checkin from %s", target.UUID, remoteAddr)
		return fmt.Errorf("forbidden: duplicated checkin")
	}

	// ── Phase 3: TOFU Verification ─────────────────────────────────────────
	if existingKey != "" && target.PublicKey != existingKey {
		ips := strings.Join(target.IPs, ", ")
		msg := fmt.Sprintf("SECURITY: agent %s presented a different key — rejecting (key rotation is disabled).\n"+
			"  Rejected Payload Info:\n    User: %s\n    Host: %s\n    IPs:  %s\n    OS:   %s\n"+
			"  If this is a legitimate reinstall, run `forget_agent %s` to reset its identity.",
			target.UUID, target.User, target.Hostname, ips, target.OS, strconv.Quote(target.UUID))
		logging.Errorf("%s", msg)
		operatorBroadcastPrintf(logging.ERROR, "%s", msg)
		return fmt.Errorf("forbidden: key rotation")
	}

	target.From = remoteAddr
	target.LastSeen = time.Now()

	// ── Phase 4: State Update ──────────────────────────────────────────────
	if placeholder != nil {
		// Replace placeholder/old entry with the new authoritative data
		live.AgentControlMap.Delete(placeholder)
		// Preservepinned key if it was already known
		if existingKey != "" {
			target.PublicKey = existingKey
		}
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
			logging.Warningf("Failed to record agent check-in: %v", err)
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
