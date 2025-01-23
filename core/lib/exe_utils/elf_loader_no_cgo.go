//go:build !cgo
// +build !cgo

package exe_utils

import "fmt"

// ELFRun runs an ELF binary with the given arguments and environment variables, completely in memory.
func ELFRun(_ []byte, _ []string, _ []string) error {
	return fmt.Errorf("ELFRun not supported without cgo")
}
