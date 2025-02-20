package tools

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

// SignByServer sign data with server private key
func SignByServer(data []byte) (sig string, err error) {
	// read private key
	priv, err := tun.ParseKeyPemFile(runtime_def.ServerKeyFile)
	if err != nil {
		log.Printf("SignByServer: %v", err)
		return "", fmt.Errorf("sign: %v", err)
	}
	// sign data
	sig_data, err := tun.SignECDSA(data, priv)
	if err != nil {
		log.Printf("SignByServer: %v", err)
		return "", fmt.Errorf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig_data), nil
}
