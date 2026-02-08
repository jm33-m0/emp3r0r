package preflight

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func TestPreflightFlow(t *testing.T) {
	// 1. Setup keys
	agentKey := []byte("12345678901234567890123456789012") // 32 bytes
	def.AESPassword = agentKey

	// 2. Create Request (Agent side)
	req := PreflightRequest{
		AgentUUID: "test-uuid-123",
		Timestamp: time.Now().Unix(),
	}
	// Sign UUID (Simplified for test)
	sum := sha256.Sum256([]byte(req.AgentUUID + string(agentKey)))
	req.AgentUUIDSig = sum[:]

	// 3. Serialize & Encrypt (Agent side)
	reqData, err := cbor.Marshal(req)
	if err != nil {
		t.Fatalf("Agent: marshal failed: %v", err)
	}
	encryptedReq, err := transport.Encrypt(reqData)
	if err != nil {
		t.Fatalf("Agent: encrypt failed: %v", err)
	}

	// --- Network Transmission Simulation ---

	// 4. Decrypt & Deserialize (Server side)
	decryptedReq, err := transport.Decrypt(encryptedReq)
	if err != nil {
		t.Fatalf("Server: decrypt failed: %v", err)
	}

	var parsedReq PreflightRequest
	if err := cbor.Unmarshal(decryptedReq, &parsedReq); err != nil {
		t.Fatalf("Server: unmarshal failed: %v", err)
	}

	// 5. Verify Request (Server side)
	if parsedReq.AgentUUID != req.AgentUUID {
		t.Errorf("UUID mismatch: got %v, want %v", parsedReq.AgentUUID, req.AgentUUID)
	}
	if parsedReq.Timestamp != req.Timestamp {
		t.Errorf("Timestamp mismatch: got %v, want %v", parsedReq.Timestamp, req.Timestamp)
	}

	// Verify Sig
	expectedSum := sha256.Sum256([]byte(parsedReq.AgentUUID + string(agentKey)))
	if !bytes.Equal(parsedReq.AgentUUIDSig, expectedSum[:]) {
		t.Errorf("Signature mismatch")
	}

	// 6. Create Response (Server side)
	resp := PreflightResponse{
		Status:      "OK",
		Instruction: "None",
	}

	// 7. Serialize & Encrypt (Server side)
	respData, err := cbor.Marshal(resp)
	if err != nil {
		t.Fatalf("Server: marshal response failed: %v", err)
	}
	encryptedResp, err := transport.Encrypt(respData)
	if err != nil {
		t.Fatalf("Server: encrypt response failed: %v", err)
	}

	// --- Network Transmission Simulation ---

	// 8. Decrypt & Deserialize (Agent side)
	decryptedResp, err := transport.Decrypt(encryptedResp)
	if err != nil {
		t.Fatalf("Agent: decrypt response failed: %v", err)
	}
	var parsedResp PreflightResponse
	if err := cbor.Unmarshal(decryptedResp, &parsedResp); err != nil {
		t.Fatalf("Agent: unmarshal response failed: %v", err)
	}

	// 9. Verify Response (Agent side)
	if parsedResp.Status != resp.Status {
		t.Errorf("Status mismatch: got %v, want %v", parsedResp.Status, resp.Status)
	}
	if parsedResp.Instruction != resp.Instruction {
		t.Errorf("Instruction mismatch: got %v, want %v", parsedResp.Instruction, resp.Instruction)
	}
}
