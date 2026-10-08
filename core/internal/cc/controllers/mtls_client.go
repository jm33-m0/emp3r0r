package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

// MTLSClientConfig contains mTLS client configuration
type MTLSClientConfig struct {
	ClientCertFile string
	ClientKeyFile  string
	CACertFile     string
	Timeout        time.Duration
	// DialContext, when set, is used to open the TCP connection before the
	// TLS handshake (e.g. to route through a userspace WireGuard stack).
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// CreateMTLSClient creates an HTTP/2 client with mTLS authentication
func CreateMTLSClient(cfg MTLSClientConfig) (*http.Client, error) {
	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		},
		RootCAs: caCertPool,
	}

	// Create HTTP/2 transport
	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
		ReadIdleTimeout: 10 * time.Second,
		PingTimeout:     5 * time.Second,
	}

	// Route the TCP connection through a custom dialer (userspace WireGuard)
	// when one is provided, then perform the TLS handshake on top of it.
	if cfg.DialContext != nil {
		dialCtx := cfg.DialContext
		transport.DialTLSContext = func(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
			raw, err := dialCtx(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		}
	}

	// Set timeout policy:
	// - timeout > 0: use caller-provided timeout
	// - timeout == 0: apply safe default timeout (30s)
	// - timeout < 0: disable global client timeout (required for long-lived streams)
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	} else if timeout < 0 {
		timeout = 0
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return client, nil
}
