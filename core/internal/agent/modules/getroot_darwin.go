//go:build darwin
// +build darwin

package modules

import (
	"fmt"
)

// Copy current executable to a new location
func CopySelfTo(dest_file string) (err error) {
	return fmt.Errorf("Not implemented")
}

// runLPEHelper runs helper scripts to give you hints on how to escalate privilege
func runLPEHelper(method, checksum string) (out string) {
	return "Not implemented"
}
