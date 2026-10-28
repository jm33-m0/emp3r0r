package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	empcrypto "github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

// encryptConfigEndingWithZero builds a valid AES-GCM config container whose
// ciphertext ends in 0x00. Zero padding in the fixed-size slot must never be
// trimmed, or this ciphertext loses part of its authentication tag.
func encryptConfigEndingWithZero(t *testing.T, plaintext []byte) []byte {
	t.Helper()

	const (
		saltSize  = 16
		nonceSize = 12
	)
	salt := bytes.Repeat([]byte{0x42}, saltSize)
	key := empcrypto.DeriveKey([]byte(def.MagicString), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}

	for i := 0; i < 1<<20; i++ {
		nonce := make([]byte, nonceSize)
		binary.BigEndian.PutUint64(nonce[nonceSize-8:], uint64(i))
		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
		if ciphertext[len(ciphertext)-1] != 0 {
			continue
		}
		container := append(append([]byte{}, salt...), nonce...)
		return append(container, ciphertext...)
	}
	t.Fatal("could not build a ciphertext ending in 0x00")
	return nil
}

func TestExtractDataAcceptsCiphertextEndingInZero(t *testing.T) {
	plaintext := []byte(`{"cc_address":"127.0.0.1"}`)
	ciphertext := encryptConfigEndingWithZero(t, plaintext)
	slot, err := def.PackAgentConfig(ciphertext)
	if err != nil {
		t.Fatalf("PackAgentConfig: %v", err)
	}

	old := def.AgentConfig
	def.AgentConfig = slot
	defer func() { def.AgentConfig = old }()

	got, err := ExtractData()
	if err != nil {
		t.Fatalf("ExtractData: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("ExtractData = %q, want %q", got, plaintext)
	}
}
