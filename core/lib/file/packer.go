package file

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/jm33-m0/arc"
)

// Base64Encode encodes a byte slice to a base64 URL-encoded string
func Base64Encode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// Base64Decode decodes a base64 URL-encoded string to a byte slice
func Base64Decode(text string) []byte {
	dec, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		log.Printf("Base64Decode: %v", err)
		return nil
	}
	return dec
}

// Bin2String compresses a binary file and encodes it with base64
func Bin2String(data []byte) (res string) {
	// Get the compressed binary data
	compressedBin, err := arc.CompressBz2(data)
	if err != nil {
		log.Printf("Bin2String: %v", err)
		return
	}

	// Encode the compressed data to base64
	res = Base64Encode(compressedBin)
	if res == "" {
		log.Println("Bin2String failed, empty string generated")
	}

	return
}

// ExtractFileFromString base64 decodes and decompresses using BZ2
func ExtractFileFromString(data string) ([]byte, error) {
	// Decode base64
	decoded := Base64Decode(data)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("ExtractFileFromString: Failed to decode")
	}

	// Get the decompressed data
	return arc.DecompressBz2(decoded)
}
