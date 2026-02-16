package client

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

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

// GetPortFwdSessions fetches active port forwarding sessions from the server
func GetPortFwdSessions() ([]def.PortFwdSession, error) {
	body, err := SendCBORRequest(transport.OperatorListPortFwds, nil)
	if err != nil {
		return nil, err
	}

	var sessions []def.PortFwdSession
	if err := cbor.Unmarshal(body, &sessions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal port mappings: %v", err)
	}

	return sessions, nil
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

// RegisterPortFwd registers a new port forwarding session with the server
func RegisterPortFwd(req def.PortFwdRequest) error {
	_, err := SendCBORRequest(transport.OperatorRegisterPortFwd, req)
	return err
}

// UnregisterPortFwd unregisters a port forwarding session from the server
func UnregisterPortFwd(sessionID string) error {
	_, err := SendCBORRequest(transport.OperatorUnregisterPortFwd, sessionID)
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
