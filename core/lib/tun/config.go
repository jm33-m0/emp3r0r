package tun

import (
	"fmt"
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
	// set up logger
	Logger = logging.NewLogger(2)

	// Paths
	EmpWorkSpace = fmt.Sprintf("%s/.emp3r0r", os.Getenv("HOME"))
	CA_CERT_FILE = fmt.Sprintf("%s/ca-cert.pem", EmpWorkSpace)
	CA_KEY_FILE = fmt.Sprintf("%s/ca-key.pem", EmpWorkSpace)
	ServerCrtFile = fmt.Sprintf("%s/server-cert.pem", EmpWorkSpace)
	ServerKeyFile = fmt.Sprintf("%s/server-key.pem", EmpWorkSpace)

	err := LoadCACrt()
	if err != nil {
		LogFatalError("Failed to load CA cert: %v", err)
	}
}

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	// CA cert
	ca_data, err := os.ReadFile(CA_CERT_FILE)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
	}
	CACrtPEM = ca_data
	return nil
}
