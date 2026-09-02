package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func buildOperatorStreamClaim(streamID, capability string) (*def.OperatorStreamClaim, error) {
	if SessionID == "" {
		return nil, fmt.Errorf("operator session is empty")
	}
	if streamID == "" {
		return nil, fmt.Errorf("stream id is empty")
	}
	if capability == "" {
		return nil, fmt.Errorf("capability is empty")
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	now := time.Now().Unix()
	claim := &def.OperatorStreamClaim{
		OperatorSession: SessionID,
		StreamID:        streamID,
		Capability:      capability,
		IssuedAt:        now,
		ExpiresAt:       now + 120,
		Nonce:           base64.RawURLEncoding.EncodeToString(nonceBytes),
	}

	priv, err := transport.ParseKeyPemFile(transport.OperatorClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("parse operator key: %w", err)
	}
	canonical := transport.CanonicalOperatorStreamClaimString(claim)
	sig, err := transport.SignECDSA([]byte(canonical), priv)
	if err != nil {
		return nil, fmt.Errorf("sign operator stream claim: %w", err)
	}
	claim.Signature = sig

	return claim, nil
}

// GetAgentList fetches the list of connected agents from the server
func GetAgentList() ([]*def.Emp3r0rAgent, error) {
	body, err := SendCBORRequest(transport.OperatorListConnectedAgents, nil)
	if err != nil {
		return nil, err
	}

	var agents []*def.Emp3r0rAgent
	if err := cbor.Unmarshal(body, &agents); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agents: %v", err)
	}
	for _, a := range agents {
		util.SanitizeAgentMetadata(a)
	}

	return agents, nil
}

// GetCerts fetches CA and Server certificates from the server
func GetCerts() (map[string][]byte, error) {
	body, err := SendCBORRequest(transport.OperatorGetCA, nil)
	if err != nil {
		return nil, err
	}

	var certs map[string][]byte
	if err := cbor.Unmarshal(body, &certs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certs: %v", err)
	}

	return certs, nil
}

// SignAgent requests the server to sign an agent UUID
func SignAgent(uuid string) (string, error) {
	req := def.SignRequest{
		Content: []byte(uuid),
	}
	body, err := SendCBORRequest(transport.OperatorSignAgent, req)
	if err != nil {
		return "", err
	}

	var sig string
	if err := cbor.Unmarshal(body, &sig); err != nil {
		return "", fmt.Errorf("failed to unmarshal signature: %v", err)
	}

	return sig, nil
}

// RegisterFTPStream registers a new FTP stream with the server
func RegisterFTPStream(token, file_path string, expectedSize int64, checksum string) error {
	claim, err := buildOperatorStreamClaim(token, def.OperatorCapabilityRegisterFTP)
	if err != nil {
		return err
	}
	req := def.FTPStreamRequest{
		Token:        token,
		FilePath:     file_path,
		ExpectedSize: expectedSize,
		Checksum:     checksum,
		Claim:        claim,
	}
	_, err = SendCBORRequest(transport.OperatorRegisterFTPStream, req)
	return err
}

// UnregisterFTPStream unregisters an FTP stream from the server
func UnregisterFTPStream(token, file_path string) error {
	req := def.FTPStreamRequest{
		Token:    token,
		FilePath: file_path,
	}
	_, err := SendCBORRequest(transport.OperatorUnregisterFTPStream, req)
	return err
}

// SetActiveAgent notifies the server that the operator is now targeting a specific agent
func SetActiveAgent(agentTag string) (*def.Emp3r0rAgent, error) {
	operation := def.Operation{
		AgentTag: agentTag,
		Action:   "command",
	}

	body, err := SendCBORRequest(transport.OperatorSetActiveAgent, operation)
	if err != nil {
		return nil, err
	}

	var agent *def.Emp3r0rAgent
	if err := cbor.Unmarshal(body, &agent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal active agent: %v", err)
	}
	util.SanitizeAgentMetadata(agent)

	return agent, nil
}

// SendCommand sends a command to an agent
func SendCommand(operation def.Operation) error {
	_, err := SendCBORRequest(transport.OperatorSendCommand, operation)
	return err
}

// UpdateOperatorIdleConfig updates the server-side operator idle timeout.
func UpdateOperatorIdleConfig(timeout int) error {
	_, err := SendCBORRequest(transport.OperatorUpdateConfig, def.OperatorIdleConfig{
		OperatorIdleTimeout: timeout,
	})
	return err
}

// ResumeOperator asks the server to clear the operator idle state and allow
// agents to reconnect.
func ResumeOperator() error {
	_, err := SendCBORRequest(transport.OperatorResume, nil)
	return err
}

// StartSocks5Proxy asks the C2 server to start a SOCKS5 pivot listener bound to
// the given agent. Operator traffic (e.g. proxychains over WireGuard) reaching
// that listener is relayed through the agent.
func StartSocks5Proxy(agentTag string, port int, bindAddr string) error {
	_, err := SendCBORRequest(transport.OperatorSocks5Start, def.Socks5ProxyRequest{
		AgentTag: agentTag,
		Port:     port,
		BindAddr: bindAddr,
	})
	return err
}

// StopSocks5Proxy asks the C2 server to stop a running SOCKS5 pivot listener.
func StopSocks5Proxy(port int) error {
	_, err := SendCBORRequest(transport.OperatorSocks5Stop, def.Socks5ProxyRequest{Port: port})
	return err
}

// ListSocks5Proxies asks the C2 server which SOCKS5 pivots are currently
// running, so the operator console can auto-populate ports and addresses.
func ListSocks5Proxies() ([]def.Socks5ProxyStatus, error) {
	body, err := SendCBORRequest(transport.OperatorSocks5List, nil)
	if err != nil {
		return nil, err
	}
	var proxies []def.Socks5ProxyStatus
	if err := cbor.Unmarshal(body, &proxies); err != nil {
		return nil, fmt.Errorf("unmarshal socks5 proxies: %w", err)
	}
	return proxies, nil
}
