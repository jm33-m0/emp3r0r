package listener

import (
	"crypto/rc4"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// rc4Crypt encrypts/decrypts data in-place using the RC4 stream cipher.
// RC4 is symmetric, so the same function is used by the listener (encryption)
// and by the stager (decryption).
func rc4Crypt(data, key []byte) error {
	if len(key) == 0 {
		return nil
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create RC4 cipher: %v", err)
	}
	cipher.XORKeyStream(data, data)
	return nil
}

func buildServedBlob(payloadPath, keyStr string) ([]byte, error) {
	// ReadFileAgent handles both mem:// and disk paths
	payload, err := util.ReadFileAgent(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %v", err)
	}

	key := deriveKeyFromString(keyStr)
	blob := make([]byte, len(payload))
	copy(blob, payload)
	if err := rc4Crypt(blob, key); err != nil {
		return nil, err
	}
	logging.Infof("Serving staged blob: payload=%d bytes", len(blob))
	return blob, nil
}
