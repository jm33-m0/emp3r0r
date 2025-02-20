package transport

import (
	"crypto/sha256"
	"fmt"
)

func sha256SumRaw(data []byte) string {
	// file sha256sum
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
