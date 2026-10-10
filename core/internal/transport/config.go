package transport

import (
	"os"
	"sync"
)

var (
	CaCrtFile     string // Path to CA cert file
	CaKeyFile     string // Path to CA key file
	ServerCrtFile string // Path to server cert file
	ServerKeyFile string // Path to server key file
	ServerPubKey  string // PEM encoded server public key
	EmpWorkSpace  string // Path to emp3r0r workspace
	CACrtPEM      []byte // CA cert in PEM format
	caCrtPEMMutex sync.RWMutex
)

// SetCACrtPEM sets the CA cert PEM safely
func SetCACrtPEM(pem []byte) {
	caCrtPEMMutex.Lock()
	defer caCrtPEMMutex.Unlock()
	CACrtPEM = pem
}

// GetCACrtPEM gets the CA cert PEM safely
func GetCACrtPEM() []byte {
	caCrtPEMMutex.RLock()
	defer caCrtPEMMutex.RUnlock()
	return CACrtPEM
}

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	ca_data, err := os.ReadFile(CaCrtFile)
	if err != nil {
		return err
	}
	SetCACrtPEM(ca_data)
	return nil
}
