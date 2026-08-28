//go:build !(windows && amd64 && cgo)

// Package smw is unavailable in this build; the syscall package falls back
// to its plain indirect-syscall path.
package smw

import "fmt"

// Ready reports whether the SilentMoonwalk spoofed path is available.
func Ready() bool {
	return false
}

// Call always fails in builds without windows/amd64+cgo; the syscall package
// never routes through it in that case.
func Call(ssn uint32, gadget uintptr, args []uintptr) (uint32, error) {
	return 0, fmt.Errorf("SilentMoonwalk requires windows/amd64 with cgo enabled")
}
