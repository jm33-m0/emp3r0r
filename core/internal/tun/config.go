package tun

import (
	"fmt"
	"os"
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
	// Paths
	EmpWorkSpace = fmt.Sprintf("%s/.emp3r0r", os.Getenv("HOME"))
	CA_CERT_FILE = fmt.Sprintf("%s/ca-cert.pem", EmpWorkSpace)
	CA_KEY_FILE = fmt.Sprintf("%s/ca-key.pem", EmpWorkSpace)
	ServerCrtFile = fmt.Sprintf("%s/server-cert.pem", EmpWorkSpace)
	ServerKeyFile = fmt.Sprintf("%s/server-key.pem", EmpWorkSpace)
}

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	ca_data, err := os.ReadFile(CA_CERT_FILE)
	if err != nil {
		return err
	}
	CACrtPEM = ca_data
	return nil
}
