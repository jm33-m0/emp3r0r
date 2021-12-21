package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"time"
)

const (
	Sep = "c7c53de5-c719-4c12-be88-c227a59b4286"
	Key = "fb9dce35-8190-4a88-a832-64a39b975ccf-ThisIsYourAESKey"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStr(n int) string {
	mathRand.Seed(time.Now().Unix())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mathRand.Intn(len(letters))]
	}
	return string(b)
}

func RandInt() int {
	mathRand.Seed(time.Now().Unix())
	return mathRand.Intn(10)
}

// MD5Sum calc md5 of a string
func MD5Sum(text string) string {
	sumbytes := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", sumbytes)
}

// generate AES key from any string
func GenAESKey(seed string) []byte {
	md5sum := MD5Sum(seed)
	return []byte(md5sum[:])[:32]
}

func AESEncrypt(key, plaintext []byte) []byte {
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

func AESDecrypt(key, ciphertext []byte) []byte {
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
