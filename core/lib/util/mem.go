package util

import (
	"bytes"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

// ExtractData extract embedded data from args[0] or process memory
func ExtractData() (data []byte, err error) {
	data, err = extractFromAgentConfig()
	if err != nil {
		err = fmt.Errorf("extract data from agent config: %v", err)
		return
	}

	if len(data) <= 0 {
		err = fmt.Errorf("no data extracted")
	}

	return
}

func extractFromAgentConfig() ([]byte, error) {
	// Try raw bytes first; some payloads legitimately end with 0x00.
	if data, err := VerifyConfigData(def.AgentConfig); err == nil {
		return data, nil
	}

	// Fallback: trim trailing zeros for legacy padded blobs.
	encConfig := bytes.TrimRight(def.AgentConfig, "\x00")
	return VerifyConfigData(encConfig)
}

func VerifyConfigData(data []byte) (jsonData []byte, err error) {
	// decrypt attached JSON file
	jsonData, err = crypto.AES_GCM_Decrypt([]byte(def.MagicString), data)
	if err != nil {
		err = fmt.Errorf("decrypt config JSON failed (%v), invalid config data?", err)
		return
	}

	return
}
