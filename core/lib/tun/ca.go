package tun

import (
	"crypto/x509"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/file"
)

// ExtractCABundle extracts built-in Ubuntu CA bundle
func ExtractCABundle() (*x509.CertPool, error) {
	ca_pem, err := file.ExtractFileFromString(file.CA_BUNDLE)
	if err != nil {
		return nil, fmt.Errorf("extractCABundle: %v", err)
	}

	// import CA bundle
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(ca_pem); !ok {
		return nil, fmt.Errorf("no CA certs appended")
	}

	return rootCAs, nil
}
