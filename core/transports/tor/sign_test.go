//go:build linux

package tor_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// signUUID signs the agent UUID with the CA private key.
func signUUID(uuidStr, keyFile string) (string, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return "", fmt.Errorf("decode CA key PEM")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(uuidStr))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(sig), nil
}
