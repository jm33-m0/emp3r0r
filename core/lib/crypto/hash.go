package crypto

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
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

// IsSHA256Hex reports whether s is a hex-encoded SHA-256 digest. Agents that
// cannot hash a file on stat report a placeholder, so callers use this to tell
// a real digest from a status string.
func IsSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// Base64URLEncode encode a string with base64
func Base64URLEncode(text string) string {
	return base64.URLEncoding.EncodeToString([]byte(text))
}

// Base64URLDecode decode a base64 encoded string (to []byte)
func Base64URLDecode(text string) []byte {
	dec, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return nil
	}
	return dec
}
