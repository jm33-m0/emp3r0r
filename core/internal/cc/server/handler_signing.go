package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// handleSignAgent handles operator requests to sign an agent UUID with the CA key.
func handleSignAgent(wrt http.ResponseWriter, req *http.Request) {
	operatorID, ok := requireOperatorIdentity(wrt, req)
	if !ok {
		return
	}
	var signReq def.SignRequest
	decoder := cbor.NewDecoder(req.Body)
	if err := decoder.Decode(&signReq); err != nil {
		logging.Errorf("handleSignAgent: failed to decode request: %v", err)
		http.Error(wrt, "Failed to decode request", http.StatusBadRequest)
		return
	}

	content := strings.TrimSpace(string(signReq.Content))
	// The CA key is the server's ultimate authority. Only ever sign the agent
	// UUID the operator is about to embed, never arbitrary content.
	if content == "" {
		http.Error(wrt, "Empty content", http.StatusBadRequest)
		return
	}
	if _, parseErr := uuid.Parse(content); parseErr != nil {
		http.Error(wrt, "Content must be a UUID", http.StatusBadRequest)
		return
	}

	sig, err := transport.SignWithCAKey([]byte(content))
	if err != nil {
		logging.Errorf("handleSignAgent: failed to sign content: %v", err)
		http.Error(wrt, fmt.Sprintf("Failed to sign content: %v", err), http.StatusInternalServerError)
		return
	}

	sigStr := base64.URLEncoding.EncodeToString(sig)
	auditOperatorAction(operatorID, "sign_agent", "", content)
	data, err := cbor.Marshal(sigStr)
	if err != nil {
		logging.Errorf("handleSignAgent: failed to marshal response: %v", err)
		http.Error(wrt, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	wrt.Header().Set("Content-Type", "application/cbor")
	wrt.WriteHeader(http.StatusOK)
	wrt.Write(data)
}

// SignAgentToken issues a signed AgentToken for the given agent and capability.
// SignWithCAKey hashes the payload internally, so we pass the raw payload string.
func SignAgentToken(agentID, ip, capability string, duration time.Duration) (*def.AgentToken, error) {
	expiresAt := time.Now().Add(duration).Unix()
	payload := fmt.Sprintf("%s%s%s%d", agentID, ip, capability, expiresAt)
	// Do NOT pre-hash: SignWithCAKey hashes the data internally (sha256).
	sig, err := transport.SignWithCAKey([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("SignAgentToken: %v", err)
	}

	tok := &def.AgentToken{
		AgentID:    agentID,
		IP:         ip,
		Capability: capability,
		ExpiresAt:  expiresAt,
		Signature:  sig,
	}
	logging.Infof("Issued AgentToken(cap=%s) for %s (expires in %v)", capability, agentID, duration)
	return tok, nil
}
