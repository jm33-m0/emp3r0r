package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ComputeHMAC computes a hex-encoded HMAC-SHA256 signature for data.
func ComputeHMAC(data []byte, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC returns true if signature matches the HMAC of data.
func VerifyHMAC(data []byte, signature string, key []byte) bool {
	expected := ComputeHMAC(data, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ComputeSharedSecret performs ECDH using a private and peer public key.
func ComputeSharedSecret(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH compute failed: %v", err)
	}
	return secret, nil
}

// SignDataECDSA signs data with the provided ECDSA private key using SHA256.
func SignDataECDSA(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, priv, hash[:])
}

// VerifySignatureECDSA verifies the ASN.1 signature over data with the provided ECDSA public key.
func VerifySignatureECDSA(pub *ecdsa.PublicKey, data, sig []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pub, hash[:], sig)
}

// GenerateEphemeralKey generates an ephemeral ECDH key pair on curve P256.
func GenerateEphemeralKey() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}
