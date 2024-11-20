package file

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/mholt/archives"
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
	var compressedBuf bytes.Buffer
	// Wrap the underlying writer with BZ2 compressor
	compressor, err := archives.Bz2{}.OpenWriter(&compressedBuf)
	if err != nil {
		log.Printf("Bin2String: %v", err)
		return
	}
	defer compressor.Close()

	// Compress the data
	_, err = compressor.Write(data)
	if err != nil {
		log.Printf("Bin2String: Write to compressor failed: %v", err)
		return
	}

	// Get the compressed binary data
	compressedBin := compressedBuf.Bytes()

	// Encode the compressed data to base64
	res = Base64Encode(compressedBin)
	if res == "" {
		log.Println("Bin2String failed, empty string generated")
	}

	return
}

// ExtractFileFromString base64 decodes and decompresses using BZ2
func ExtractFileFromString(data string) (out []byte, err error) {
	// Decode base64
	decoded := Base64Decode(data)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("ExtractFileFromString: Failed to decode")
	}

	var decompressBuf bytes.Buffer
	// Wrap the underlying reader with BZ2 decompressor
	decompressor, err := archives.Bz2{}.OpenReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("ExtractFileFromString: %v", err)
	}
	defer decompressor.Close()

	// Decompress the data
	_, err = decompressBuf.ReadFrom(decompressor)
	if err != nil {
		return nil, fmt.Errorf("ExtractFileFromString: Read from decompressor failed: %v", err)
	}

	// Get the decompressed data
	out = decompressBuf.Bytes()
	return
}
