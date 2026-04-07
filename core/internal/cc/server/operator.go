package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/posener/h2conn"
)

// represents an operator_t
type operator_t struct {
	sessionID string       // marks the operator session
	conn      *h2conn.Conn // message tunnel, used to relay messages
}

var (
	// OPERATORS holds all operator connections
	OPERATORS sync.Map

	// SERVER_WG_CONFIG is the wireguard config for the server
	SERVER_WG_CONFIG *netutil.WireGuardConfig
)

// DecodeCBORBody decodes CBOR HTTP request body
func DecodeCBORBody[T any](wrt http.ResponseWriter, req *http.Request) (*T, error) {
	var dst T
	if err := cbor.NewDecoder(req.Body).Decode(&dst); err != nil {
		http.Error(wrt, err.Error(), http.StatusBadRequest)
		return nil, err
	}
	return &dst, nil
}

func handleSetActiveAgent(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleSetActiveAgent panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body
	operation, err := DecodeCBORBody[def.Operation](wrt, req)
	if err != nil {
		return
	}

	// Set active agent
	agents.SetActiveAgent(operation.AgentTag)

	// Return active agent
	wrt.Header().Set("Content-Type", "application/cbor")
	if err := cbor.NewEncoder(wrt).Encode(live.ActiveAgent); err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
	}
}

func handleSendCommand(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleSendCommand panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body
	operation, err := DecodeCBORBody[def.Operation](wrt, req)
	if err != nil {
		return
	}

	// Get agent
	agent := agents.GetAgentByTag(operation.AgentTag)
	if agent == nil {
		http.Error(wrt, "Agent not found", http.StatusNotFound)
		return
	}

	// Get command and job ID
	if !operation.IsOptionSet("command") || !operation.IsOptionSet("job_id") {
		http.Error(wrt, "Command or JobID is empty", http.StatusBadRequest)
		return
	}

	// Track the job ID so the message tunnel accepts the response
	live.CmdTime.Store(*operation.JobID, time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"))

	// Send command to agent
	err = agents.SendCmd(*operation.Command, *operation.JobID, agent)
	if err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
		return
	}
	wrt.WriteHeader(http.StatusOK)
}

func handleListAgents(wrt http.ResponseWriter, _ *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleListAgents panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Get all agents
	agentsList := agents.GetConnectedAgents()

	wrt.Header().Set("Content-Type", "application/cbor")
	if err := cbor.NewEncoder(wrt).Encode(agentsList); err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
	}
}

func handleForgetAgent(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleForgetAgent panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body to get Agent UUID
	operation, err := DecodeCBORBody[def.Operation](wrt, req)
	if err != nil {
		return
	}

	uuid := operation.AgentTag
	if uuid == "" {
		http.Error(wrt, "Agent UUID is empty", http.StatusBadRequest)
		return
	}

	// Prepare response message with agent details
	var agentDetails string = fmt.Sprintf("Agent %s", uuid)

	// Try to get agent details from memory first (if connected/recently connected)
	var targetAgent *def.Emp3r0rAgent
	live.AgentControlMap.Range(func(key, value any) bool {
		a := key.(*def.Emp3r0rAgent)
		if a.UUID == uuid {
			targetAgent = a
			return false // stop iteration
		}
		return true
	})
	if targetAgent != nil && targetAgent.Tag != "" {
		agentDetails += fmt.Sprintf("\n  Tag: %s\n  Hostname: %s\n  IPs: %s\n  OS: %s",
			targetAgent.Tag, targetAgent.Hostname, strings.Join(targetAgent.IPs, ", "), targetAgent.OS)
	} else if agents.AgentDB != nil {
		// Try to get from DB
		stored, err := agents.GetStoredAgent(uuid)
		// Try DB fallback even if targetAgent is a placeholder
		if err == nil && stored != nil {
			agentDetails += fmt.Sprintf("\n  Tag: %s\n  Hostname: %s\n  IPs: %s\n  OS: %s\n  (Offline/Database Record)",
				stored.Tag, stored.Hostname, stored.IPAddresses, stored.OS)
		}
	}

	// Remove from DB
	if agents.AgentDB != nil {
		err := agents.RemoveAgent(uuid)
		if err != nil {
			logging.Errorf("Failed to remove agent %s from DB: %v", uuid, err)
			http.Error(wrt, fmt.Sprintf("DB removal failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(wrt, "Agent database not initialized", http.StatusInternalServerError)
		return
	}

	// Remove from memory
	if targetAgent != nil {
		live.AgentControlMap.Delete(targetAgent)
		controllers.CleanupPortFwdsByAgent(targetAgent)
		logging.Successf("Operator removed agent %s from memory", uuid)
	}
	wrt.WriteHeader(http.StatusOK)
	fmt.Fprintf(wrt, "%s\n\nHas been forgotten.", agentDetails)
}

func handleListPortFwds(wrt http.ResponseWriter, _ *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleListPortFwds panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()

	var sessions []def.PortFwdSession
	network.PortFwds.Range(func(id, value any) bool {
		portmap := value.(*network.PortFwdSession)
		bindAddr := portmap.BindAddr
		if bindAddr == "" {
			bindAddr = "127.0.0.1"
		}

		sessions = append(sessions, def.PortFwdSession{
			ID:          id.(string),
			LocalPort:   portmap.Lport,
			RemoteAddr:  portmap.To,
			BindAddr:    bindAddr,
			AgentTag:    portmap.Agent.Tag,
			Description: portmap.Description,
			Reverse:     portmap.Reverse,
			Protocol:    portmap.Protocol,
		})
		return true
	})

	data, err := cbor.Marshal(sessions)
	if err != nil {
		logging.Errorf("Failed to marshal port mappings: %v", err)
		http.Error(wrt, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	wrt.Header().Set("Content-Type", "application/cbor")
	wrt.WriteHeader(http.StatusOK)
	wrt.Write(data)
}

func handleRegisterPortFwd(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleRegisterPortFwd panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body
	pfReq, err := DecodeCBORBody[def.PortFwdRequest](wrt, req)
	if err != nil {
		return
	}

	// Register session in server's map.
	// If a runtime session already exists, update metadata in-place instead of replacing
	// the object, so we don't drop live fields like Ctx/Cancel/Sh and crash stream handling.
	if existing, ok := network.PortFwds.Load(pfReq.SessionID); ok {
		if pf, ok := existing.(*network.PortFwdSession); ok && pf != nil {
			pf.Lport = pfReq.Lport
			pf.To = pfReq.To
			pf.Description = pfReq.Description
			pf.Protocol = pfReq.Protocol
			pf.Reverse = pfReq.IsReverse
			if pf.Agent == nil {
				pf.Agent = &def.Emp3r0rAgent{}
			}
			pf.Agent.Tag = pfReq.AgentTag
			if pf.ShReady == nil {
				pf.ShReady = make(chan struct{})
			}
			if pf.Ctx == nil || pf.Cancel == nil {
				pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
			}
		} else {
			network.PortFwds.Store(pfReq.SessionID, &network.PortFwdSession{
				Lport:       pfReq.Lport,
				To:          pfReq.To,
				Description: pfReq.Description,
				Protocol:    pfReq.Protocol,
				Reverse:     pfReq.IsReverse,
				Agent: &def.Emp3r0rAgent{
					Tag: pfReq.AgentTag,
				},
				ShReady: make(chan struct{}),
				Ctx:     context.Background(),
				Cancel:  func() {},
			})
		}
	} else {
		network.PortFwds.Store(pfReq.SessionID, &network.PortFwdSession{
			Lport:       pfReq.Lport,
			To:          pfReq.To,
			Description: pfReq.Description,
			Protocol:    pfReq.Protocol,
			Reverse:     pfReq.IsReverse,
			Agent: &def.Emp3r0rAgent{
				Tag: pfReq.AgentTag,
			},
			ShReady: make(chan struct{}),
			Ctx:     context.Background(),
			Cancel:  func() {},
		})
	}

	logging.Infof("Registered port mapping %s (%s) from operator", pfReq.SessionID, pfReq.Description)
	wrt.WriteHeader(http.StatusOK)
}

func handleUnregisterPortFwd(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleUnregisterPortFwd panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body
	sessionID, err := DecodeCBORBody[string](wrt, req)
	if err != nil {
		return
	}

	// Unregister session in server's map
	network.PortFwds.Delete(*sessionID)

	logging.Infof("Unregistered port mapping %s from operator", *sessionID)
	wrt.WriteHeader(http.StatusOK)
}

func handleGetCA(wrt http.ResponseWriter, _ *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleGetCA panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	caData, err := os.ReadFile(transport.CaCrtFile)
	if err != nil {
		logging.Errorf("Failed to read CA cert: %v", err)
		http.Error(wrt, "Failed to read CA cert", http.StatusInternalServerError)
		return
	}

	serverCrtData, err := os.ReadFile(transport.ServerCrtFile)
	if err != nil {
		logging.Errorf("Failed to read Server cert: %v", err)
		http.Error(wrt, "Failed to read Server cert", http.StatusInternalServerError)
		return
	}

	resp := map[string][]byte{
		"ca_crt":     caData,
		"server_crt": serverCrtData,
	}

	data, err := cbor.Marshal(resp)
	if err != nil {
		logging.Errorf("Failed to marshal certs: %v", err)
		http.Error(wrt, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	wrt.Header().Set("Content-Type", "application/cbor")
	wrt.WriteHeader(http.StatusOK)
	wrt.Write(data)
}

// handleOperatorConn handles operator connections, this connection will be used to relay the message tunnel
func handleOperatorConn(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleOperatorConn panicked: %v", r)
		}
	}()
	conn, err := h2conn.Accept(wrt, req)
	if err != nil {
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	operator_session := req.Header.Get("operator_session")

	// Check if other operators are already connected
	activeSessionCount := 0
	OPERATORS.Range(func(key, value any) bool {
		activeSessionCount++
		return true
	})
	if activeSessionCount > 0 {
		logging.Warningf("⚠️  New operator %s connecting while %d session(s) active!", operator_session, activeSessionCount)

		// Construct a warning message
		warningMsg := def.MsgTunData{
			Tag: "ERROR", // "ERROR" tag triggers red text in your UI
			Response: []byte(fmt.Sprintf(
				"\n\n⛔  ERROR: %d other operator session(s) are currently active!\n"+
					"   Concurrent usage is PROHIBITED to prevent state corruption.\n"+
					"   Closing connection... Please retry when the other session is closed.\n", activeSessionCount)),
		}

		// Send the warning immediately upon connection
		encoder := cbor.NewEncoder(conn)
		if err := encoder.Encode(warningMsg); err != nil {
			logging.Errorf("Failed to send concurrency warning: %v", err)
		}
		time.Sleep(100 * time.Millisecond) // Ensure the message is sent
		conn.Close()
		return
	}
	logging.Infof("Operator %s connected to message tunnel from %s", operator_session, req.RemoteAddr)
	op, _ := OPERATORS.LoadOrStore(operator_session, &operator_t{
		sessionID: operator_session,
		conn:      conn,
	})
	operator := op.(*operator_t)
	operator.conn = conn
	OPERATORS.Store(operator_session, operator)

	ctx, cancel := context.WithCancel(req.Context())
	defer func() {
		logging.Debugf("handleOperatorConn exiting")
		OPERATORS.Delete(operator_session)

		// If this was the last operator, disconnect all agents
		lastOperator := true
		OPERATORS.Range(func(key, value any) bool {
			lastOperator = false
			return false // stop iteration
		})

		if lastOperator {
			logging.Infof("Last operator disconnected, closing all agent connections")
			agents.DisconnectAllAgents()
		}

		_ = conn.Close()
		cancel()
	}()

	// Create a ticker to send heartbeat messages
	heartbeatTicker := time.NewTicker(1 * time.Second)
	defer heartbeatTicker.Stop()

	// Create a timeout timer for 1 minute (60 seconds)
	timeoutTimer := time.NewTimer(1 * time.Minute)
	defer timeoutTimer.Stop()

	// Channel to track the latest heartbeat
	heartbeatCh := make(chan struct{})

	// receiving heartbeats from the operator
	for {
		select {
		case <-heartbeatTicker.C:
			// If no heartbeat received in the last minute, close the connection
			if !timeoutTimer.Stop() {
				<-timeoutTimer.C
				logging.Warningf("Operator %s heartbeat timeout, closing connection", operator_session)
				conn.Close()
				cancel()
				return
			}
			// Reset the timeout timer after receiving a heartbeat
			timeoutTimer.Reset(1 * time.Minute)
		case <-heartbeatCh:
			// Heartbeat received, reset the timeout
			timeoutTimer.Reset(1 * time.Minute)
		case <-ctx.Done():
			logging.Warningf("handleOperatorConn exited")
			return
		}
	}
}
