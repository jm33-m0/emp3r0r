//go:build !cgo
// +build !cgo

package exe_utils

import "fmt"

// Dummy implementation of InMemExeRun for systems without cgo
func InMemExeRun(_ []byte, _ []string, _ []string) error {
	return fmt.Errorf("ELFRun not supported without cgo")
}
