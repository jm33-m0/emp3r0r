package tools

import (
	"encoding/base64"
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// SignByServer sign data with server private key
func SignByServer(data []byte) (sig string, err error) {
	// read private key
	priv, err := transport.ParseKeyPemFile(transport.ServerKeyFile)
	if err != nil {
		logging.Printf("SignByServer: %v", err)
		return "", fmt.Errorf("sign: %v", err)
	}
	// sign data
	sig_data, err := transport.SignECDSA(data, priv)
	if err != nil {
		logging.Printf("SignByServer: %v", err)
		return "", fmt.Errorf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig_data), nil
}
