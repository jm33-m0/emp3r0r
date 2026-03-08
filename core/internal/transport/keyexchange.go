package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"net"

	"golang.org/x/crypto/hkdf"
)

// PerformECDH performs Elliptic Curve Diffie-Hellman key exchange
// Returns the shared secret derived from the private key and peer's public key
func PerformECDH(privateKey *ecdsa.PrivateKey, peerPublicKey *ecdsa.PublicKey) ([]byte, error) {
	if privateKey == nil || peerPublicKey == nil {
		return nil, fmt.Errorf("private key or peer public key is nil")
	}

	// Verify that both keys use the same curve
	if privateKey.Curve != peerPublicKey.Curve {
		return nil, fmt.Errorf("key curve mismatch: private key uses %v, peer key uses %v",
			privateKey.Curve.Params().Name, peerPublicKey.Curve.Params().Name)
	}

	// Perform ECDH: multiply peer's public key by our private key
	// sharedX, sharedY = peerPublicKey * privateKey.D
	sharedX, sharedY := peerPublicKey.Curve.ScalarMult(peerPublicKey.X, peerPublicKey.Y, privateKey.D.Bytes())

	if sharedX == nil {
		return nil, fmt.Errorf("ECDH failed: shared secret is nil")
	}

	// Use only the X coordinate as the shared secret (standard practice)
	// Pad to curve size to ensure consistent length
	curveSize := (privateKey.Curve.Params().BitSize + 7) / 8
	sharedSecret := make([]byte, curveSize)
	sharedXBytes := sharedX.Bytes()
	copy(sharedSecret[curveSize-len(sharedXBytes):], sharedXBytes)

	// Prevent compiler optimization from removing sharedY
	_ = sharedY

	return sharedSecret, nil
}

// DeriveSessionKey derives an AES-256 key from the ECDH shared secret using HKDF
// The agentUUID is used as additional context to ensure unique keys per agent
func DeriveSessionKey(sharedSecret []byte, agentUUID string) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret is empty")
	}

	// HKDF parameters
	salt := []byte("session-key-salt-v1")
	info := []byte(fmt.Sprintf("client-session:%s", agentUUID))

	// Create HKDF reader
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)

	// Derive 32 bytes (256 bits) for AES-256
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %v", err)
	}

	return sessionKey, nil
}

// GenerateEphemeralKeyPair generates a new ephemeral ECDSA key pair for ECDH
// This is used by the C2 server to generate a unique key for each agent session
func GenerateEphemeralKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewSecureConnWithKey creates a SecureConn with a custom session key
// This is used after ECDH key exchange to create an encrypted connection
func NewSecureConnWithKey(conn io.ReadWriteCloser, sessionKey []byte) *SecureConn {
	// If conn is not a net.Conn, wrap it
	var netConn net.Conn
	var ok bool
	if netConn, ok = conn.(net.Conn); !ok {
		netConn = &ByteReadWriteCloser{conn}
	}

	return &SecureConn{
		Conn:    netConn,
		key:     sessionKey,
		readBuf: make([]byte, 0),
	}
}

// SerializePublicKey converts an ECDSA public key to a byte slice
// Format: [X bytes][Y bytes] where each coordinate is padded to curve size
func SerializePublicKey(pubKey *ecdsa.PublicKey) []byte {
	if pubKey == nil {
		return nil
	}

	curveSize := (pubKey.Curve.Params().BitSize + 7) / 8
	serialized := make([]byte, 2*curveSize)

	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	copy(serialized[curveSize-len(xBytes):curveSize], xBytes)
	copy(serialized[2*curveSize-len(yBytes):], yBytes)

	return serialized
}

// DeserializePublicKey converts a byte slice back to an ECDSA public key
// Assumes P-256 curve
func DeserializePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	curveSize := (curve.Params().BitSize + 7) / 8

	if len(data) != 2*curveSize {
		return nil, fmt.Errorf("invalid public key length: got %d, expected %d", len(data), 2*curveSize)
	}

	x := new(big.Int).SetBytes(data[:curveSize])
	y := new(big.Int).SetBytes(data[curveSize:])

	// Verify point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
