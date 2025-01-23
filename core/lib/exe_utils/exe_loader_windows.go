//go:build windows && cgo
// +build windows,cgo

package exe_utils

import "fmt"

import "C"

// TODO: Implement InMemExeRun for Windows
func InMemExeRun(_ []byte, _ []string, _ []string) error {
	return fmt.Errorf("ELFRun not supported without cgo")
}
