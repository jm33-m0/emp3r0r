package tun

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Go implementation of PKCS5Padding
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

// XOREncrypt
func XOREncrypt(key []byte, plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ key[i%len(key)]
	}
	return ciphertext
}

const (
	saltSize   = 16
	keySize    = 32
	nonceSize  = 12
	iterations = 100000
)

func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, bytes)
	return bytes, err
}

func DeriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keySize, sha256.New)
}

// AES_GCM_Encrypt encrypts plaintext with password using AES-GCM
func AES_GCM_Encrypt(password, plaintext []byte) ([]byte, error) {
	// Generate random salt and derive key using PBKDF2
	salt, err := GenerateRandomBytes(saltSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	key := DeriveKey(password, salt)

	// Generate random nonce for AES-GCM
	nonce, err := GenerateRandomBytes(nonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	// Encrypt and append nonce and salt
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Concatenate salt, nonce, and ciphertext
	buffer := bytes.NewBuffer(salt)
	buffer.Write(nonce)
	buffer.Write(ciphertext)

	return buffer.Bytes(), nil
}

// AES_GCM_Decrypt decrypts ciphertext with password using AES-GCM
func AES_GCM_Decrypt(password, ciphertext []byte) ([]byte, error) {
	// Extract salt, nonce, and actual ciphertext
	salt := ciphertext[:saltSize]
	nonce := ciphertext[saltSize : saltSize+nonceSize]
	encMessage := ciphertext[saltSize+nonceSize:]

	// Derive key from password and salt
	key := DeriveKey(password, salt)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	// Decrypt the ciphertext
	plaintext, err := aesgcm.Open(nil, nonce, encMessage, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}
