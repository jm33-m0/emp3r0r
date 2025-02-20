package transport

import (
	"crypto/x509"
	"fmt"
)

// ExtractCABundle extracts built-in Ubuntu CA bundle
func ExtractCABundle(ca_pem []byte) (*x509.CertPool, error) {
	// import CA bundle
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(ca_pem); !ok {
		return nil, fmt.Errorf("no CA certs appended")
	}

	return rootCAs, nil
}
