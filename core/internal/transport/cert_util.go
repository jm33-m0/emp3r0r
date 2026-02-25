package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateEphemeralCert creates a self-signed certificate/key pair in memory.
// It randomizes the Subject to look like internal infrastructure (e.g., "node-x7f").
// If org or cn are provided, they will be used instead of random values.
func GenerateEphemeralCert(org, cn string) (tls.Certificate, error) {
	// 1. Generate Ephemeral Key (P-256)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 2. Randomize Serial Number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// 3. Set or Generate Random Hostname for Camouflage
	if cn == "" {
		randomHex := make([]byte, 2)
		rand.Read(randomHex)
		cn = fmt.Sprintf("node-%x", randomHex)
	}

	if org == "" {
		orgs := []string{"System Infrastructure", "Kubernetes Cluster", "Internal Services", "Mesh Node"}
		maxLimit := big.NewInt(int64(len(orgs)))
		n, _ := rand.Int(rand.Reader, maxLimit)
		org = orgs[n.Int64()]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),      // Valid since yesterday
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// 4. Self-Sign the Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 5. Return as tls.Certificate
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
