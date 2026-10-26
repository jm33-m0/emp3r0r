package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
)

// ServerCertificate is the currently loaded C2 TLS certificate. It is kept
// behind an RWMutex and replaced as a whole so a concurrent handshake always
// sees a complete cert/key pair.
var (
	serverCertMu sync.RWMutex
	serverCert   *tls.Certificate
)

// ReloadServerTLSCert loads the configured server certificate/key pair and
// publishes it for new TLS and QUIC handshakes. Existing connections keep using
// the certificate they negotiated with.
func ReloadServerTLSCert() error {
	cert, err := tls.LoadX509KeyPair(ServerCrtFile, ServerKeyFile)
	if err != nil {
		return fmt.Errorf("load server TLS keypair: %w", err)
	}
	serverCertMu.Lock()
	serverCert = &cert
	serverCertMu.Unlock()
	return nil
}

// GetServerTLSCert returns the certificate for a new TLS handshake. It is used
// as tls.Config.GetCertificate so a cert update is picked up without restarting
// the listener.
func GetServerTLSCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverCertMu.RLock()
	cert := serverCert
	serverCertMu.RUnlock()
	if cert == nil {
		return nil, errors.New("server TLS certificate is not loaded")
	}
	return cert, nil
}
