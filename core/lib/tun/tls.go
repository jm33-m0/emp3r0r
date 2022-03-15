package tun

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"
)

var (

	// CACrt for TLS server cert signing
	// fill our CA pem text when compiling
	// taken care by build.sh
	CACrt = []byte(`
-----BEGIN CERTIFICATE-----
MIIC4TCCAcmgAwIBAgIUcbZPJSEhP8JNIlvgPK8cwArOF3swDQYJKoZIhvcNAQEL
BQAwADAeFw0yMjAyMDIwODE0NTJaFw0zMjAxMzEwODE0NTJaMAAwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2TknslyCkJxXkqI6Le9OuM0yFNFHIrLXy
uSTEJCMYp578Rai/ag7pAKm39XY5UTdL3bOcJ5XOkNudqrnvK6ZUkCVVlIjcLcMq
NZv5zFIddLdav8kxsElNmJ31TkYOkOsA69vZYDvGDPkwtlHEk77C63ff8x1Vgos8
H8dmsV33A/L+doieYNEXPaTHRTYtynh2Est2Oao5YH/cc+GUqJ22RDFxVqf/NyD6
+o/Ik4bt1hpTn3Dkf03w/E9dNzU0dNpPuRLCOmIBAdbB3gyeA79zrLkDlxLe6BTI
8+D2e0aLnSaMrpF58HEVFT2LMtxnc0rVCmoul2GaQl9pK47xJNKtAgMBAAGjUzBR
MB0GA1UdDgQWBBTQVI/uRRB76cg49W6HLuMFpGZDyzAfBgNVHSMEGDAWgBTQVI/u
RRB76cg49W6HLuMFpGZDyzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQCcow5XQVpw1PldtVsYm1qKkHVZbsBHhsNfPmJ+WUCqku03qZw5BfguZZhf
CsI7qkCT6oOl/MOGs/Q3rN/mq1v09MG+aujch5a3R6TJ7XoAIv2zEf1AQ4htzJI0
JINsh2s0vIIeBAPXXGijuODZQvVoSLZhA42YPPlq3Wq0y87Gm17yaF+MRztOdV2r
DmD2opUBwNGzpnI2BZv0JhQjcgGJTgDGVpNx5Hlk46L8O8iP7dKzvt+oOd7KT/rt
9qESTi/STrTrMHgf8jK2r4EFIiuNQrcbJfFRL8j/0C2r8wDq68qP/cYVHp13KDdZ
67F8+PqRu68+eK6AGZeIa6NtH1PI
-----END CERTIFICATE-----

		`)
)

// EmpHTTPClient add our CA to trusted CAs, while keeps TLS InsecureVerify on
func EmpHTTPClient(proxyServer string) *http.Client {
	// start with an empty pool
	rootCAs := x509.NewCertPool()

	// add our cert
	if ok := rootCAs.AppendCertsFromPEM(CACrt); !ok {
		log.Println("No certs appended")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	// return our http client
	tr := &http.Transport{TLSClientConfig: config}

	// use a proxy for our HTTP client
	if proxyServer != "" {
		proxyUrl, err := url.Parse(proxyServer)
		if err != nil {
			log.Fatalf("Invalid proxy: %v", err)
		}
		tr.Proxy = http.ProxyURL(proxyUrl)
	}
	err := http2.ConfigureTransport(tr) // upgrade to HTTP2, while keeping http.Transport
	if err != nil {
		log.Fatalf("Cannot switch to HTTP2: %v", err)
	}

	return &http.Client{Transport: tr}
}
