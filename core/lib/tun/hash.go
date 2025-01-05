package tun

import (
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

// MD5Sum calc md5 of a string
func MD5Sum(text string) string {
	return crypto.MD5Sum(text)
}

// SHA256Sum calc sha256 of a string
func SHA256Sum(text string) string {
	return crypto.SHA256Sum(text)
}

// SHA256SumFile calc sha256 of a file (of any size)
func SHA256SumFile(path string) string {
	return crypto.SHA256SumFile(path)
}

func SHA256SumRaw(data []byte) string {
	return crypto.SHA256SumRaw(data)
}

// Base64URLEncode encode a string with base64
func Base64URLEncode(text string) string {
	return crypto.Base64URLEncode(text)
}

// Base64URLDecode decode a base64 encoded string (to []byte)
func Base64URLDecode(text string) []byte {
	return crypto.Base64URLDecode(text)
}
