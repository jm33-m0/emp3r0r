package preflight

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// Check performs the preflight check
func Check(config *def.Config) bool {
	if !config.PreflightEnabled {
		return true
	}

	url := config.PreflightURL
	if url == "" {
		logging.Debugf("Preflight enabled but no URL? Assume success.")
		return true
	}

	logging.Printf("Performing Preflight Check: %s", url)

	// 1. Prepare Payload
	timestamp := time.Now().Unix()
	reqData := PreflightRequest{
		AgentUUID: config.AgentUUID,
		Timestamp: timestamp,
	}
	logging.Debugf("Preflight: sending request with timestamp=%d", timestamp)
	// Sign
	sig, err := agentutils.SignWithAgentKey([]byte(config.AgentUUID))
	if err == nil {
		reqData.AgentUUIDSig = sig
	}

	rawBytes, err := cbor.Marshal(reqData)
	if err != nil {
		logging.Errorf("Preflight: cbor marshal: %v", err)
		return false
	}

	encrypted, err := transport.Encrypt(rawBytes)
	if err != nil {
		logging.Errorf("Preflight: encrypt: %v", err)
		return false
	}

	// 2. Prepare Request (POST)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(encrypted))
	if err != nil {
		logging.Errorf("Preflight: NewRequest: %v", err)
		return false
	}

	// Set Headers (Malleable)
	for k, v := range config.PreflightHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/octet-stream") // Or malleable?

	client := transport.CreatePreflightHTTPClient(config.PreflightURL)
	if client == nil {
		logging.Errorf("Preflight: failed to create HTTP client for %s", config.PreflightURL)
		return false
	}

	// 3. Send
	resp, err := client.Do(req)
	if err != nil {
		logging.Errorf("Preflight: Do: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logging.Errorf("Preflight: status %d", resp.StatusCode)
		return false
	}

	// 4. Decrypt Response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Errorf("Preflight: read body: %v", err)
		return false
	}

	decryptedResp, err := transport.Decrypt(respBody)
	if err != nil {
		logging.Errorf("Preflight: decrypt response: %v", err)
		return false
	}

	var pfResp PreflightResponse
	if err := cbor.Unmarshal(decryptedResp, &pfResp); err != nil {
		logging.Errorf("Preflight: unmarshal response: %v", err)
		return false
	}

	if pfResp.Status != "AC" {
		logging.Errorf("Preflight: denied (status=%s)", pfResp.Status)
		return false
	}

	logging.Printf("Preflight Success! %s", pfResp.Instruction)
	return true
}
