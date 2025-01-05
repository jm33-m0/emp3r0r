package tun

import (
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

// Go implementation of PKCS5Padding
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	return crypto.PKCS5Padding(ciphertext, blockSize)
}

func PKCS5Trimming(encrypt []byte) []byte {
	return crypto.PKCS5Trimming(encrypt)
}

// XOREncrypt
func XOREncrypt(key []byte, plaintext []byte) []byte {
	return crypto.XOREncrypt(key, plaintext)
}

func GenerateRandomBytes(size int) ([]byte, error) {
	return crypto.GenerateRandomBytes(size)
}

func DeriveKey(password, salt []byte) []byte {
	return crypto.DeriveKey(password, salt)
}

// AES_GCM_Encrypt encrypts plaintext with password using AES-GCM
func AES_GCM_Encrypt(password, plaintext []byte) ([]byte, error) {
	return crypto.AES_GCM_Encrypt(password, plaintext)
}

// AES_GCM_Decrypt decrypts ciphertext with password using AES-GCM
func AES_GCM_Decrypt(password, ciphertext []byte) ([]byte, error) {
	return crypto.AES_GCM_Decrypt(password, ciphertext)
}
