package crypto

import (
	"bytes"
	"testing"
)

// TestPKCS5Padding tests the PKCS5Padding function
func TestPKCS5Padding(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		blockSize    int
		expectedLen  int
		expectedLast byte
	}{
		{
			name:         "8 bytes with 16-byte block",
			input:        []byte("12345678"),
			blockSize:    16,
			expectedLen:  16,
			expectedLast: 8, // 8 bytes of padding
		},
		{
			name:         "empty with 16-byte block",
			input:        []byte{},
			blockSize:    16,
			expectedLen:  16,
			expectedLast: 16, // full block of padding
		},
		{
			name:         "15 bytes with 16-byte block",
			input:        make([]byte, 15),
			blockSize:    16,
			expectedLen:  16,
			expectedLast: 1, // 1 byte of padding
		},
		{
			name:         "16 bytes with 16-byte block",
			input:        make([]byte, 16),
			blockSize:    16,
			expectedLen:  32,
			expectedLast: 16, // full block of padding
		},
		{
			name:         "1 byte with 8-byte block",
			input:        []byte("a"),
			blockSize:    8,
			expectedLen:  8,
			expectedLast: 7, // 7 bytes of padding
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PKCS5Padding(tt.input, tt.blockSize)

			if len(result) != tt.expectedLen {
				t.Errorf("PKCS5Padding() length = %d, expected %d", len(result), tt.expectedLen)
			}

			if result[len(result)-1] != tt.expectedLast {
				t.Errorf("PKCS5Padding() last byte = %d, expected %d", result[len(result)-1], tt.expectedLast)
			}

			// Verify all padding bytes have the same value
			paddingLen := int(result[len(result)-1])
			for i := len(result) - paddingLen; i < len(result); i++ {
				if result[i] != byte(paddingLen) {
					t.Errorf("PKCS5Padding() padding byte at position %d = %d, expected %d", i, result[i], paddingLen)
				}
			}
		})
	}
}

// TestPKCS5Trimming tests the PKCS5Trimming function
func TestPKCS5Trimming(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "8 bytes of padding",
			input:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8},
			expected: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			name:     "1 byte of padding",
			input:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1},
			expected: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		{
			name:     "full block of padding",
			input:    []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PKCS5Trimming(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("PKCS5Trimming() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestPKCS5RoundTrip tests padding and trimming together
func TestPKCS5RoundTrip(t *testing.T) {
	blockSizes := []int{8, 16, 32}
	testData := [][]byte{
		[]byte("hello"),
		[]byte(""),
		[]byte("The quick brown fox jumps over the lazy dog"),
		make([]byte, 16),
		make([]byte, 15),
		make([]byte, 17),
	}

	for _, blockSize := range blockSizes {
		for i, data := range testData {
			t.Run(string(rune('a'+i)), func(t *testing.T) {
				padded := PKCS5Padding(data, blockSize)
				trimmed := PKCS5Trimming(padded)

				if !bytes.Equal(trimmed, data) {
					t.Errorf("Round-trip failed: got %v, expected %v", trimmed, data)
				}
			})
		}
	}
}

// TestXOREncrypt tests the XOREncrypt function
func TestXOREncrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		plaintext []byte
	}{
		{
			name:      "simple encryption",
			key:       []byte("secret"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "empty plaintext",
			key:       []byte("key"),
			plaintext: []byte{},
		},
		{
			name:      "key longer than plaintext",
			key:       []byte("verylongkey"),
			plaintext: []byte("short"),
		},
		{
			name:      "key shorter than plaintext",
			key:       []byte("key"),
			plaintext: []byte("this is a much longer plaintext"),
		},
		{
			name:      "single byte key",
			key:       []byte("x"),
			plaintext: []byte("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext := XOREncrypt(tt.key, tt.plaintext)

			if len(ciphertext) != len(tt.plaintext) {
				t.Errorf("XOREncrypt() length = %d, expected %d", len(ciphertext), len(tt.plaintext))
			}

			// Decrypt (XOR is symmetric)
			decrypted := XOREncrypt(tt.key, ciphertext)

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("XOREncrypt round-trip failed: got %v, expected %v", decrypted, tt.plaintext)
			}
		})
	}
}

// TestXOREncryptDifferentKeys tests that different keys produce different ciphertexts
func TestXOREncryptDifferentKeys(t *testing.T) {
	plaintext := []byte("test data")
	key1 := []byte("key1")
	key2 := []byte("key2")

	ciphertext1 := XOREncrypt(key1, plaintext)
	ciphertext2 := XOREncrypt(key2, plaintext)

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("XOREncrypt produced identical ciphertexts for different keys")
	}
}

// TestAES_GCM_Encrypt tests the AES_GCM_Encrypt function
func TestAES_GCM_Encrypt(t *testing.T) {
	tests := []struct {
		name      string
		password  []byte
		plaintext []byte
	}{
		{
			name:      "simple encryption",
			password:  []byte("password123"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "empty plaintext",
			password:  []byte("password"),
			plaintext: []byte{},
		},
		{
			name:      "long plaintext",
			password:  []byte("securepassword"),
			plaintext: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
		},
		{
			name:      "binary data",
			password:  []byte("key"),
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := AES_GCM_Encrypt(tt.password, tt.plaintext)
			if err != nil {
				t.Fatalf("AES_GCM_Encrypt() error = %v", err)
			}

			// Ciphertext should be longer than plaintext due to salt, nonce, and auth tag
			expectedMinLen := len(tt.plaintext) + saltSize + nonceSize + 16 // 16 is GCM tag size
			if len(ciphertext) < expectedMinLen {
				t.Errorf("AES_GCM_Encrypt() ciphertext too short: got %d bytes, expected at least %d", len(ciphertext), expectedMinLen)
			}
		})
	}
}

// TestAES_GCM_Decrypt tests the AES_GCM_Decrypt function
func TestAES_GCM_Decrypt(t *testing.T) {
	password := []byte("testpassword")
	plaintext := []byte("test message")

	// First encrypt
	ciphertext, err := AES_GCM_Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("AES_GCM_Encrypt() error = %v", err)
	}

	// Then decrypt
	decrypted, err := AES_GCM_Decrypt(password, ciphertext)
	if err != nil {
		t.Fatalf("AES_GCM_Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("AES_GCM_Decrypt() = %v, expected %v", decrypted, plaintext)
	}
}

// TestAES_GCM_RoundTrip tests encryption and decryption together
func TestAES_GCM_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		password  []byte
		plaintext []byte
	}{
		{
			name:      "simple text",
			password:  []byte("password"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "empty plaintext",
			password:  []byte("password"),
			plaintext: []byte{},
		},
		{
			name:      "long text",
			password:  []byte("securepassword123"),
			plaintext: []byte("The quick brown fox jumps over the lazy dog. " + "This is a longer message to test encryption of larger data."),
		},
		{
			name:      "unicode text",
			password:  []byte("密码"),
			plaintext: []byte("Hello 世界 🌍"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := AES_GCM_Encrypt(tt.password, tt.plaintext)
			if err != nil {
				t.Fatalf("AES_GCM_Encrypt() error = %v", err)
			}

			// Decrypt
			decrypted, err := AES_GCM_Decrypt(tt.password, ciphertext)
			if err != nil {
				t.Fatalf("AES_GCM_Decrypt() error = %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Round-trip failed: got %v, expected %v", decrypted, tt.plaintext)
			}
		})
	}
}

// TestAES_GCM_WrongPassword tests that wrong password fails decryption
func TestAES_GCM_WrongPassword(t *testing.T) {
	correctPassword := []byte("correct")
	wrongPassword := []byte("wrong")
	plaintext := []byte("secret message")

	// Encrypt with correct password
	ciphertext, err := AES_GCM_Encrypt(correctPassword, plaintext)
	if err != nil {
		t.Fatalf("AES_GCM_Encrypt() error = %v", err)
	}

	// Try to decrypt with wrong password
	_, err = AES_GCM_Decrypt(wrongPassword, ciphertext)
	if err == nil {
		t.Error("AES_GCM_Decrypt() should fail with wrong password, but succeeded")
	}
}

// TestAES_GCM_DifferentPasswordsDifferentCiphertexts tests that same plaintext with different passwords produces different ciphertexts
func TestAES_GCM_DifferentPasswordsDifferentCiphertexts(t *testing.T) {
	plaintext := []byte("test message")
	password1 := []byte("password1")
	password2 := []byte("password2")

	ciphertext1, err := AES_GCM_Encrypt(password1, plaintext)
	if err != nil {
		t.Fatalf("AES_GCM_Encrypt() error = %v", err)
	}

	ciphertext2, err := AES_GCM_Encrypt(password2, plaintext)
	if err != nil {
		t.Fatalf("AES_GCM_Encrypt() error = %v", err)
	}

	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Same plaintext with different passwords should produce different ciphertexts")
	}
}

// TestAES_GCM_NonDeterministic tests that encrypting the same data twice produces different ciphertexts
func TestAES_GCM_NonDeterministic(t *testing.T) {
	password := []byte("password")
	plaintext := []byte("test message")

	ciphertext1, err := AES_GCM_Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("AES_GCM_Encrypt() error = %v", err)
	}

	ciphertext2, err := AES_GCM_Encrypt(password, plaintext)
	if err != nil {
		t.Fatalf("AES_GCM_Encrypt() error = %v", err)
	}

	// Due to random salt and nonce, ciphertexts should be different
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Encrypting same data twice should produce different ciphertexts (due to random salt/nonce)")
	}

	// But both should decrypt to the same plaintext
	decrypted1, err := AES_GCM_Decrypt(password, ciphertext1)
	if err != nil {
		t.Fatalf("AES_GCM_Decrypt() error = %v", err)
	}

	decrypted2, err := AES_GCM_Decrypt(password, ciphertext2)
	if err != nil {
		t.Fatalf("AES_GCM_Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("Both ciphertexts should decrypt to the same plaintext")
	}
}

// TestGenerateRandomBytes tests the GenerateRandomBytes function
func TestGenerateRandomBytes(t *testing.T) {
	sizes := []int{0, 1, 16, 32, 64, 128}

	for _, size := range sizes {
		t.Run(string(rune('a'+size)), func(t *testing.T) {
			bytes, err := GenerateRandomBytes(size)
			if err != nil {
				t.Fatalf("GenerateRandomBytes(%d) error = %v", size, err)
			}

			if len(bytes) != size {
				t.Errorf("GenerateRandomBytes(%d) returned %d bytes", size, len(bytes))
			}
		})
	}

	// Test that multiple calls produce different results
	t.Run("generates different bytes", func(t *testing.T) {
		bytes1, err := GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("GenerateRandomBytes() error = %v", err)
		}

		bytes2, err := GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("GenerateRandomBytes() error = %v", err)
		}

		if bytes.Equal(bytes1, bytes2) {
			t.Error("GenerateRandomBytes() generated identical bytes twice")
		}
	})
}

// TestDeriveKey tests the DeriveKey function
func TestDeriveKey(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt1234salt1234")

	key := DeriveKey(password, salt)

	// Key should be 32 bytes (keySize constant)
	if len(key) != keySize {
		t.Errorf("DeriveKey() returned key of length %d, expected %d", len(key), keySize)
	}

	// Same inputs should produce same key
	key2 := DeriveKey(password, salt)
	if !bytes.Equal(key, key2) {
		t.Error("DeriveKey() is not deterministic for same inputs")
	}

	// Different password should produce different key
	key3 := DeriveKey([]byte("different"), salt)
	if bytes.Equal(key, key3) {
		t.Error("DeriveKey() produced same key for different passwords")
	}

	// Different salt should produce different key
	key4 := DeriveKey(password, []byte("differentsalt12"))
	if bytes.Equal(key, key4) {
		t.Error("DeriveKey() produced same key for different salts")
	}
}
