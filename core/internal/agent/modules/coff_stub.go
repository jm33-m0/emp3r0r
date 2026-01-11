//go:build !windows

package modules

import "fmt"

func runCOFFModule(_ []byte, _ []string) (string, error) {
	return "", fmt.Errorf("COFF modules are only supported on Windows agents")
}
