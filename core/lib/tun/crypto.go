package tun

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
)

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

// Base64URLEncode encode a string with base64
func Base64URLEncode(text string) string {
	return base64.URLEncoding.EncodeToString([]byte(text))
}

// Base64URLDecode decode a base64 encoded string (to []byte)
func Base64URLDecode(text string) []byte {
	dec, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		log.Printf("Base64Decode: %v", err)
		return nil
	}
	return dec
}
