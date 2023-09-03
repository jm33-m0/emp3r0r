package tun

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
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

// AESEncryptRaw encrypt bytes
func AESEncryptRaw(key, plaintext []byte) []byte {
	plaintext = PKCS5Padding(plaintext, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Print(err)
		return nil
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Print(err)
		return nil
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

// AESDecryptRaw decrypt bytes
func AESDecryptRaw(key, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Print(err)
		return nil
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		log.Print("ciphertext too short")
		return nil
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// make sure the ciphertext is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		log.Print("ciphertext is not a multiple of the block size")
		return nil
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	cbc.CryptBlocks(ciphertext, ciphertext)

	return PKCS5Trimming(ciphertext)
}

// AESEncrypt string to base64 crypto using AES
func AESEncrypt(key []byte, text string) string {
	plaintext := []byte(text)
	plaintext = PKCS5Padding([]byte(text), aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Print(err)
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Print(err)
		return ""
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// AESDecrypt from base64 to decrypted string
func AESDecrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Print(err)
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		log.Print("ciphertext too short")
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// make sure the ciphertext is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		log.Print("ciphertext is not a multiple of the block size")
		return ""
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	cbc.CryptBlocks(ciphertext, ciphertext)

	return fmt.Sprintf("%s", PKCS5Trimming(ciphertext))
}

// GenAESKey generate AES key from any string
func GenAESKey(seed string) []byte {
	md5sum := MD5Sum(seed)
	return []byte(md5sum)[:32]
}

// XOREncrypt
func XOREncrypt(key []byte, plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ key[i%len(key)]
	}
	return ciphertext
}
