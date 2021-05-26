package emp3r0r_data

import (
	"crypto/md5"
	"fmt"
)

// genAESKey generate AES key from any string
func genAESKey(seed string) []byte {
	md5sum := md5Sum(seed)
	return []byte(md5sum)[:32]
}

// md5Sum calc md5 of a string
func md5Sum(text string) string {
	sumbytes := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", sumbytes)
}
