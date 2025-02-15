package tun

import (
	"fmt"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var (
	CA_CERT_FILE  string // Path to CA cert file
	CA_KEY_FILE   string // Path to CA key file
	ServerCrtFile string // Path to server cert file
	ServerKeyFile string // Path to server key file
	ServerPubKey  string // PEM encoded server public key
	EmpWorkSpace  string // Path to emp3r0r workspace
	CACrtPEM      []byte // CA cert in PEM format
)

func init() {
	var err error
	// set up logger
	Logger, err = logging.NewLogger("", 2)
	if err != nil {
		log.Fatalf("tun init: failed to set up logger: %v", err)
	}

	// Paths
	EmpWorkSpace = fmt.Sprintf("%s/.emp3r0r", os.Getenv("HOME"))
	CA_CERT_FILE = fmt.Sprintf("%s/ca-cert.pem", EmpWorkSpace)
	CA_KEY_FILE = fmt.Sprintf("%s/ca-key.pem", EmpWorkSpace)
	ServerCrtFile = fmt.Sprintf("%s/server-cert.pem", EmpWorkSpace)
	ServerKeyFile = fmt.Sprintf("%s/server-key.pem", EmpWorkSpace)
}

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	LogDebug("Loading CA cert from %s", CA_CERT_FILE)
	ca_data, err := os.ReadFile(CA_CERT_FILE)
	if err != nil {
		return err
	}
	CACrtPEM = ca_data
	LogDebug("CA cert loaded, fingerprint: %s", GetFingerprint(CA_CERT_FILE))
	return nil
}
