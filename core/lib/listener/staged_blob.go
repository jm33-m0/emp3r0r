package listener

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// derivedKeyLen is the length of the RC4 key derived from the download key
// string. It must stay in sync with DERIVED_KEY_LEN in
// core/modules/stager/packer.h.
const derivedKeyLen = 16

// deriveKeyFromString derives a fixed-size RC4 key from the passphrase.
// This mirrors derive_key_from_string() in core/modules/stager/packer.c; the
// two must stay in sync or the stager will not be able to decrypt the blob.
func deriveKeyFromString(str string) []byte {
	key := make([]uint32, derivedKeyLen/4)
	for i := range key {
		for j := 0; j < len(str)/4; j++ {
			key[i] ^= uint32(str[i+j*4]) << (j % 4 * 8)
		}
	}
	keyBytes := make([]byte, derivedKeyLen)
	for i, v := range key {
		binary.LittleEndian.PutUint32(keyBytes[i*4:], v)
	}
	listenerLogf("Derived key: %08x %08x %08x %08x", key[0], key[1], key[2], key[3])
	return keyBytes
}

// rc4Crypt encrypts/decrypts data in-place using the RC4 stream cipher.
// RC4 is symmetric, so the same function is used by the listener (encryption)
// and by the stager (decryption, see core/modules/stager/rc4.c).
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
