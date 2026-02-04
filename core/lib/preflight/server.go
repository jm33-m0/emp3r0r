package preflight

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ProcessRequest handles raw body from preflight request.
// It decrypts, verifies signature/timestamp, and returns encrypted response.
// ProcessRequest handles raw body from preflight request.
// It decrypts, verifies signature/timestamp, and returns encrypted response.
func ProcessRequest(data []byte, allowConn bool) ([]byte, error) {
	// 1. Decrypt
	decrypted, err := transport.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %v", err)
	}

	// 2. Unmarshal
	var req PreflightRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}

	// 3. Verify Timestamp (within 60 seconds?)
	now := time.Now().Unix()
	diff := now - req.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > 60 {
		return nil, fmt.Errorf("invalid timestamp: request too old or future")
	}

	logging.Debugf("Preflight request from %s (ts: %d)", req.AgentUUID, req.Timestamp)

	// Determine status
	status := "RJ" // Reject by default
	instruction := "Wait for operator"
	if allowConn {
		status = "AC" // Allow Connect
		instruction = "OK"
	}

	// 5. Construct Response
	resp := PreflightResponse{
		Status:      status,
		Instruction: instruction,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	// 6. Encrypt Response
	return transport.Encrypt(respBytes)
}

// TODO: Helper to verify CA signature if we have access to CA cert in standalone mode?
// For integrated mode, we have access.
// We will leave stricter CA-check for refinement step if needed, relying on AES-GCM for now.
