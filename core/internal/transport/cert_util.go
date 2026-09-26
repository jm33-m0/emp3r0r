package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
)

// GenerateEphemeralCert creates a self-signed certificate/key pair in memory.
// The subject, serial and validity are randomized so certificates from
// different nodes do not share a recognizable identity. If org or cn are
// provided, they are used instead of random values.
func GenerateEphemeralCert(org, cn string) (tls.Certificate, error) {
	// 1. Generate Ephemeral Key (P-256)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 2. Randomize the subject when the caller did not pin one.
	if cn == "" {
		cn = randomCertCN()
	}
	if org == "" {
		org = randomCertOrg()
	}

	notBefore, notAfter := randomCertValidity(false)
	template := x509.Certificate{
		SerialNumber: randomCertSerial(),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// 3. Self-Sign the Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 4. Return as tls.Certificate
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
