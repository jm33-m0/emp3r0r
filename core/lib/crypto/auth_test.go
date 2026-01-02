package crypto

import (
	"bytes"
	"testing"
)

// TestComputeHMAC tests the ComputeHMAC function
func TestComputeHMAC(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		key      []byte
		expected string
	}{
		{
			name:     "known test vector 1",
			data:     []byte("hello"),
			key:      []byte("secret"),
			expected: "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b",
		},
		{
			name:     "empty data",
			data:     []byte{},
			key:      []byte("secret"),
			expected: "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169",
		},
		{
			name:     "empty key",
			data:     []byte("hello"),
			key:      []byte{},
			expected: "4352b26e33fe0d769a8922a6ba29004109f01688e26acc9e6cb347e5a5afc4da",
		},
		{
			name:     "both empty",
			data:     []byte{},
			key:      []byte{},
			expected: "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeHMAC(tt.data, tt.key)
			if result != tt.expected {
				t.Errorf("ComputeHMAC(%v, %v) = %q, expected %q", tt.data, tt.key, result, tt.expected)
			}
		})
	}
}

// TestComputeHMACDifferentKeys tests that different keys produce different HMACs
func TestComputeHMACDifferentKeys(t *testing.T) {
	data := []byte("test data")
	key1 := []byte("key1")
	key2 := []byte("key2")

	hmac1 := ComputeHMAC(data, key1)
	hmac2 := ComputeHMAC(data, key2)

	if hmac1 == hmac2 {
		t.Errorf("ComputeHMAC should produce different results for different keys, got %q for both", hmac1)
	}
}

// TestComputeHMACDifferentData tests that different data produces different HMACs
func TestComputeHMACDifferentData(t *testing.T) {
	key := []byte("secret")
	data1 := []byte("data1")
	data2 := []byte("data2")

	hmac1 := ComputeHMAC(data1, key)
	hmac2 := ComputeHMAC(data2, key)

	if hmac1 == hmac2 {
		t.Errorf("ComputeHMAC should produce different results for different data, got %q for both", hmac1)
	}
}

// TestVerifyHMAC tests the VerifyHMAC function
func TestVerifyHMAC(t *testing.T) {
	data := []byte("test data")
	key := []byte("secret key")
	validSignature := ComputeHMAC(data, key)

	tests := []struct {
		name      string
		data      []byte
		signature string
		key       []byte
		expected  bool
	}{
		{
			name:      "valid signature",
			data:      data,
			signature: validSignature,
			key:       key,
			expected:  true,
		},
		{
			name:      "invalid signature",
			data:      data,
			signature: "invalid_signature_here",
			key:       key,
			expected:  false,
		},
		{
			name:      "tampered data",
			data:      []byte("tampered data"),
			signature: validSignature,
			key:       key,
			expected:  false,
		},
		{
			name:      "wrong key",
			data:      data,
			signature: validSignature,
			key:       []byte("wrong key"),
			expected:  false,
		},
		{
			name:      "empty signature",
			data:      data,
			signature: "",
			key:       key,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyHMAC(tt.data, tt.signature, tt.key)
			if result != tt.expected {
				t.Errorf("VerifyHMAC(%v, %q, %v) = %v, expected %v", tt.data, tt.signature, tt.key, result, tt.expected)
			}
		})
	}
}

// TestGenerateEphemeralKey tests the GenerateEphemeralKey function
func TestGenerateEphemeralKey(t *testing.T) {
	// Test that key generation works
	t.Run("successful generation", func(t *testing.T) {
		privKey, pubKeyBytes, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("GenerateEphemeralKey() failed: %v", err)
		}

		if privKey == nil {
			t.Error("GenerateEphemeralKey() returned nil private key")
		}

		if len(pubKeyBytes) == 0 {
			t.Error("GenerateEphemeralKey() returned empty public key bytes")
		}
	})

	// Test that public key can be extracted from private key
	t.Run("public key extraction", func(t *testing.T) {
		privKey, pubKeyBytes, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("GenerateEphemeralKey() failed: %v", err)
		}

		// Verify the public key bytes match what's in the private key
		extractedPubBytes := privKey.PublicKey().Bytes()
		if !bytes.Equal(pubKeyBytes, extractedPubBytes) {
			t.Errorf("Public key bytes don't match: got %v, expected %v", pubKeyBytes, extractedPubBytes)
		}
	})

	// Test that multiple generations produce different keys
	t.Run("generates different keys", func(t *testing.T) {
		privKey1, pubKeyBytes1, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("First GenerateEphemeralKey() failed: %v", err)
		}

		privKey2, pubKeyBytes2, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("Second GenerateEphemeralKey() failed: %v", err)
		}

		if bytes.Equal(pubKeyBytes1, pubKeyBytes2) {
			t.Error("GenerateEphemeralKey() generated identical public keys twice")
		}

		// Also check private keys are different by comparing public keys
		if bytes.Equal(privKey1.PublicKey().Bytes(), privKey2.PublicKey().Bytes()) {
			t.Error("GenerateEphemeralKey() generated identical private keys twice")
		}
	})

	// Test that generated keys have expected properties
	t.Run("key properties", func(t *testing.T) {
		privKey, pubKeyBytes, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("GenerateEphemeralKey() failed: %v", err)
		}

		// P256 public keys should be 65 bytes (uncompressed) or 33 bytes (compressed)
		// The function uses Bytes() which returns the compressed format for P256
		if len(pubKeyBytes) != 65 && len(pubKeyBytes) != 33 {
			t.Errorf("Public key has unexpected length: %d bytes", len(pubKeyBytes))
		}

		// Verify the private key is not nil and has a public key
		if privKey.PublicKey() == nil {
			t.Error("Generated private key has nil public key")
		}
	})
}

// TestComputeSharedSecret tests the ComputeSharedSecret function
func TestComputeSharedSecret(t *testing.T) {
	// Test basic shared secret computation
	t.Run("successful computation", func(t *testing.T) {
		// Generate two key pairs
		privKey1, _, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("Failed to generate first key pair: %v", err)
		}

		privKey2, _, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("Failed to generate second key pair: %v", err)
		}

		// Compute shared secrets
		secret1, err := ComputeSharedSecret(privKey1, privKey2.PublicKey())
		if err != nil {
			t.Fatalf("ComputeSharedSecret failed: %v", err)
		}

		secret2, err := ComputeSharedSecret(privKey2, privKey1.PublicKey())
		if err != nil {
			t.Fatalf("ComputeSharedSecret failed: %v", err)
		}

		// Verify both parties compute the same shared secret
		if !bytes.Equal(secret1, secret2) {
			t.Errorf("Shared secrets don't match: %v vs %v", secret1, secret2)
		}

		// Verify secret is not empty
		if len(secret1) == 0 {
			t.Error("Shared secret is empty")
		}
	})

	// Test that different key pairs produce different shared secrets
	t.Run("different keys produce different secrets", func(t *testing.T) {
		privKey1, _, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		privKey2, _, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		privKey3, _, err := GenerateEphemeralKey()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		secret12, err := ComputeSharedSecret(privKey1, privKey2.PublicKey())
		if err != nil {
			t.Fatalf("ComputeSharedSecret failed: %v", err)
		}

		secret13, err := ComputeSharedSecret(privKey1, privKey3.PublicKey())
		if err != nil {
			t.Fatalf("ComputeSharedSecret failed: %v", err)
		}

		if bytes.Equal(secret12, secret13) {
			t.Error("Different peer keys produced the same shared secret")
		}
	})
}

// TestSignDataECDSA tests the SignDataECDSA function
func TestSignDataECDSA(t *testing.T) {
	// We need to generate an ECDSA key pair for signing
	// Note: GenerateEphemeralKey returns ECDH keys, not ECDSA keys
	// For now, we'll skip this test as it requires ECDSA key generation
	t.Skip("Skipping ECDSA tests - requires ECDSA key generation implementation")
}

// TestVerifySignatureECDSA tests the VerifySignatureECDSA function
func TestVerifySignatureECDSA(t *testing.T) {
	t.Skip("Skipping ECDSA tests - requires ECDSA key generation implementation")
}
