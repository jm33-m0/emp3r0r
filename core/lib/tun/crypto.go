package tun

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
)

// AESEncryptRaw encrypt bytes
func AESEncryptRaw(key, plaintext []byte) []byte {
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

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

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

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext
}

// AESEncrypt string to base64 crypto using AES
func AESEncrypt(key []byte, text string) string {
	plaintext := []byte(text)

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

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

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

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

// GenAESKey generate AES key from any string
func GenAESKey(seed string) []byte {
	md5sum := MD5Sum(seed)
	return []byte(md5sum)[:32]
}

// MD5Sum calc md5 of a string
func MD5Sum(text string) string {
	sumbytes := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", sumbytes)
}

// SHA256Sum calc sha256 of a string
func SHA256Sum(text string) string {
	sumbytes := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", sumbytes)
}

// SHA256SumFile calc sha256 of a file (of any size)
func SHA256SumFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return err.Error()
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err.Error()
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func SHA256SumRaw(data []byte) string {
	// file sha256sum
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// Base64Encode encode a string with base64
func Base64Encode(text string) string {
	return base64.URLEncoding.EncodeToString([]byte(text))
}

// Base64Decode decode a base64 encoded string (to []byte)
func Base64Decode(text string) []byte {
	dec, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		log.Printf("Base64Decode: %v", err)
		return nil
	}
	return dec
}
