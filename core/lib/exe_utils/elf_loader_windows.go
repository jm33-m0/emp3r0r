//go:build windows && cgo
// +build windows,cgo

package exe_utils

import "fmt"

import "C"

// ELFRun runs an ELF binary with the given arguments and environment variables, completely in memory.
func ELFRun(_ []byte, _ []string, _ []string) error {
	return fmt.Errorf("ELFRun not supported without cgo")
}
