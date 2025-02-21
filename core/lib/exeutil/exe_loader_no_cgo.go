//go:build !cgo
// +build !cgo

package exeutil

import "fmt"

// Dummy implementation of InMemExeRun for systems without cgo
func InMemExeRun(_ []byte, _ []string, _ []string) (string, error) {
	return "", fmt.Errorf("ELFRun not supported without cgo")
}
