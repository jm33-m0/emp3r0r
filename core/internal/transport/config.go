package transport

import (
	"os"
)

var (
	CaCrtFile             string // Path to CA cert file
	CaKeyFile             string // Path to CA key file
	ServerCrtFile         string // Path to server cert file
	ServerKeyFile         string // Path to server key file
	ServerPubKey          string // PEM encoded server public key
	OperatorCaCrtFile     string // Path to operator CA cert file
	OperatorCaKeyFile     string // Path to operator CA key file
	OperatorServerCrtFile string // Path to operator cert file
	OperatorServerKeyFile string // Path to operator key file
	OperatorClientCrtFile string // operator client mTLS cert
	OperatorClientKeyFile string // operator client mTLS key
	EmpWorkSpace          string // Path to emp3r0r workspace
	CACrtPEM              []byte // CA cert in PEM format
)

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	ca_data, err := os.ReadFile(CaCrtFile)
	if err != nil {
		return err
	}
	CACrtPEM = ca_data
	return nil
}
