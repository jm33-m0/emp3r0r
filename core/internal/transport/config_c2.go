//go:build !agent

package transport

import (
	"fmt"
	"os"
)

func init() {
	// Paths
	EmpWorkSpace = fmt.Sprintf("%s/.emp3r0r", os.Getenv("HOME"))
	CaCrtFile = fmt.Sprintf("%s/ca-cert.pem", EmpWorkSpace)
	CaKeyFile = fmt.Sprintf("%s/ca-key.pem", EmpWorkSpace)
	ServerCrtFile = fmt.Sprintf("%s/server-cert.pem", EmpWorkSpace)
	ServerKeyFile = fmt.Sprintf("%s/server-key.pem", EmpWorkSpace)
	OperatorCaCrtFile = fmt.Sprintf("%s/operator-ca-cert.pem", EmpWorkSpace)
	OperatorCaKeyFile = fmt.Sprintf("%s/operator-ca-key.pem", EmpWorkSpace)
	OperatorServerCrtFile = fmt.Sprintf("%s/operator-server-cert.pem", EmpWorkSpace)
	OperatorServerKeyFile = fmt.Sprintf("%s/operator-server-key.pem", EmpWorkSpace)
	OperatorClientCrtFile = fmt.Sprintf("%s/operator-client-cert.pem", EmpWorkSpace)
	OperatorClientKeyFile = fmt.Sprintf("%s/operator-client-key.pem", EmpWorkSpace)
}
