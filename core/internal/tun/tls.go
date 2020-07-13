package tun

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

var (

	// CACrt for TLS server cert signing
	// fill our CA pem text when compiling
	// taken care by build.sh
	CACrt = []byte(`
[emp3r0r_ca]
		`)
)

// EmpHTTPClient add our CA to trusted CAs, while keeps TLS InsecureVerify on
func EmpHTTPClient(proxyServer string) *http.Client {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(CACrt); !ok {
		log.Println("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// return our http client
	tr := &http2.Transport{TLSClientConfig: config}

	// TODO use a socks5 proxy
	// currently it's a hack, as there's no official way of configuring a proxy for HTTP2
	if proxyServer != "" {
		dialer, err := proxy.SOCKS5("tcp", proxyServer, nil, proxy.Direct)
		proxyDialer := func(network string, addr string, cfg *tls.Config) (c net.Conn, e error) {
			c, e = dialer.Dial(network, addr) // this is a TCP dialer, thus no TLS, not usable
			return
		}
		if err != nil {
			log.Printf("failed to set proxy: %v", err)
		}
		tr.DialTLS = proxyDialer
	}

	return &http.Client{Transport: tr}
}
