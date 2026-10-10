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
}
