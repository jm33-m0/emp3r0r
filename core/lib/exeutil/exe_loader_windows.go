//go:build windows && cgo
// +build windows,cgo

package exeutil

import "fmt"

import "C"

// TODO: Implement InMemExeRun for Windows
func InMemExeRun(_ []byte, _ []string, _ []string) (string, error) {
	return "", fmt.Errorf("ELFRun not supported without cgo")
}

// TODO: Implement InMemExePTYRun for Windows
func InMemExePTYRun(_ []byte, _ []string, _ []string, _ int) (int, error) {
	return -1, fmt.Errorf("InMemExePTYRun not supported on Windows yet")
}
