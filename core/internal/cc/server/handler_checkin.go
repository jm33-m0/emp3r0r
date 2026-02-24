package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// rotationRateLimiter tracks key rotation timestamps per AgentUUID to prevent log flooding
var rotationRateLimiter sync.Map

// handleAgentCheckIn processes agent check-in requests.
func handleAgentCheckIn(wrt http.ResponseWriter, req *http.Request, expectedUUID string) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleAgentCheckIn panic: %v\n%s", r, util.CallStack())
			http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}()
	expectedUUID = util.StripANSI(expectedUUID)
	if expectedUUID == "" {
		logging.Warningf("handleAgentCheckIn: empty expected UUID")
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// check if agent is already connected (duplicated checkin)
	// strictly by UUID (token in URL must match authenticated header UUID)
	vars := mux.Vars(req)
	token := util.StripANSI(vars["token"])
	if token == "" || token != expectedUUID {
		logging.Warningf("handleAgentCheckIn: token/UUID mismatch: token=%s expected=%s", strconv.Quote(token), strconv.Quote(expectedUUID))
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if agents.IsAgentExistByUUID(expectedUUID) {
		agent := agents.GetAgentByUUID(expectedUUID)
		if agent != nil {
			if val, ok := live.AgentControlMap.Load(agent); ok {
				ctrl := val.(*live.AgentControl)
				if ctrl.Conn != nil {
					logging.Warningf("handleAgentCheckIn: %s already connected, refusing duplicated checkin", expectedUUID)
					wrt.WriteHeader(http.StatusForbidden)
					return
				}
			}
		}
	}

	conn, err := h2conn.Accept(wrt, req)
	defer func() {
		_ = conn.Close()
		if logging.Level >= 4 {
			logging.Debugf("handleAgentCheckIn finished")
		}
	}()
	if err != nil {
		logging.Errorf("handleAgentCheckIn: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// Global Encryption: Wrap connection
	secureConn := transport.NewSecureConn(conn)
	// target is a pointer to Emp3r0rAgent
	target := new(def.Emp3r0rAgent)
	in := cbor.NewDecoder(secureConn) // Use secureConn
	err = in.Decode(target)
	if err != nil {
		logging.Warningf("handleAgentCheckIn decode error: %v", err)
		return
	}
	// sanitize agent data
	agents.SanitizeAgentData(target)

	// Header UUID was already CA-validated in dispatcher. Body UUID MUST match.
	if target.UUID == "" || target.UUID != expectedUUID {
		logging.Warningf("handleAgentCheckIn: body UUID mismatch: body=%s expected=%s", strconv.Quote(target.UUID), strconv.Quote(expectedUUID))
		http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// SECURITY: Agent MUST provide its public key in every checkin
	// If missing, reject immediately - something is wrong (malicious, compromised, or misconfigured)
	if target.PublicKey == "" {
		logging.Warningf("handleAgentCheckIn: Agent %s provided no public key, rejecting", strconv.Quote(target.UUID))
		http.Error(wrt, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// TOFU: Trust On First Use
	// If agent exists, verify with pinned key
	// If agent is new, verify with provided key and pin it
	isNew := true

	existingKey := ""
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == target.UUID {
			// Skip placeholders that don't have a public key yet.
			// If we find an agent with a key, use it and stop.
			if a.PublicKey != "" {
				existingKey = a.PublicKey
				isNew = false
				return false // stop iteration
			}
			// If it's just a placeholder, keep searching (or let it fall through to the DB check)
		}
		return true
	})

	if isNew {
		// New agent in memory (or placeholder) - check if it's firmly pinned in the DB
		if agents.AgentDB != nil {
			stored, err := agents.GetStoredAgent(target.UUID)
			logging.Infof("DEBUG-CHECKIN: GetStoredAgent(%s) returned stored=%v, err=%v", target.UUID, stored != nil, err)
			if err == nil && stored != nil { // Only consider if no error and agent found
				existingKey = stored.PublicKey
				isNew = false
			} else if err != nil {
				logging.Errorf("handleAgentCheckIn: GetStoredAgent error: %v", err)
			}
		}
	}

	if len(existingKey) > 10 {
		logging.Infof("DEBUG-CHECKIN: isNew=%v, existingKey_len=%d, targetKey_len=%d, existingKey=(%s...)", isNew, len(existingKey), len(target.PublicKey), existingKey[:10])
	} else {
		logging.Infof("DEBUG-CHECKIN: isNew=%v, existingKey_len=%d, targetKey_len=%d, existingKey=(%s)", isNew, len(existingKey), len(target.PublicKey), existingKey)
	}

	if !isNew {
		// Existing agent: key MUST match the pinned key. Key rotation is never allowed.
		if existingKey != "" && target.PublicKey != existingKey {
			ips := strings.Join(target.IPs, ", ")
			msg := fmt.Sprintf("SECURITY: agent %s presented a different key — rejecting (key rotation is disabled).\n"+
				"  Rejected Payload Info:\n    User: %s\n    Host: %s\n    IPs:  %s\n    OS:   %s\n"+
				"  If this is a legitimate reinstall, run `forget_agent %s` to reset its identity.",
				target.UUID, target.User, target.Hostname, ips, target.OS, strconv.Quote(target.UUID))
			logging.Errorf("%s", msg)
			operatorBroadcastPrintf(logging.ERROR, "%s", msg)
			http.Error(wrt, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	// CA signature already verified via HTTP headers in dispatcher
	target.From = req.RemoteAddr

	logging.Infof("DEBUG-CHECKIN: Database pointer in handler_checkin is %p", agents.AgentDB)

	// Update agent in memory (dispatcher already created placeholder)
	// Find the placeholder and update it with full agent data from CBOR
	var existingCtrl *live.AgentControl
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == target.UUID {
			existingCtrl = value.(*live.AgentControl)
			if existingCtrl.Conn != nil {
				logging.Warningf("handleAgentCheckIn: %s just connected, but state says it is already connected. This implies a ghost session.", target.Tag)
			}
			// TOFU: Public key remains pinned for existing agents
			target.PublicKey = a.PublicKey

			// Remove the old pointer so we can replace it cleanly
			live.AgentControlMap.Delete(key)
			return false
		}
		return true
	})

	// Store updated agent pointer with full data into the map
	target.LastSeen = time.Now()
	if existingCtrl != nil {
		live.AgentControlMap.Store(target, existingCtrl)
	} else {
		inx := agents.AssignAgentIndex()
		live.AgentControlMap.Store(target, &live.AgentControl{Index: inx, Conn: nil})
	}

	logging.Infof("Updated agent %q with full data from CBOR", target.UUID)

	// Signal that public key is now available (for any waiting requests)
	closeCheckinReadyChannel(target.UUID)
	logging.Debugf("Signaled checkin completion for %s", strconv.Quote(target.UUID))

	// Now that agent is in memory with pubkey, safe to proceed with other operations
	// (message tunnel requests can now resolve the pubkey)

	// ------------------------------------------------------------ // SECURITY: DoS Protection (Rate Limiting)
	// ------------------------------------------------------------
	now := time.Now()
	// Prune old timestamps (> 1 minute)
	validTimestamps := []time.Time{}
	if val, exists := rotationRateLimiter.Load(target.UUID); exists {
		timestamps := val.([]time.Time)
		for _, t := range timestamps {
			if now.Sub(t) < time.Minute {
				validTimestamps = append(validTimestamps, t)
			}
		}
	}
	validTimestamps = append(validTimestamps, now)
	rotationRateLimiter.Store(target.UUID, validTimestamps)

	// Check limit (10 rotations per minute)
	if len(validTimestamps) > 10 {
		// Silent Drop: Stop processing to save CPU/Disk
		logging.Warningf("Rate limit exceeded for agent %s, dropping request", target.UUID)
		return
	}

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

	if isNew {
		logging.Infof("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
	} else {
		if logging.Level >= 4 {
			logging.Debugf("Agent reconnected: %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
