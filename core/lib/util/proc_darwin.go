//go:build darwin
// +build darwin

package util

import (
	"errors"
)

// Dummy implementation for darwin

func ProcUID(pid int) string {
	return ""
}

func CopyProcExeTo(pid int, dest_path string) error {
	return errors.New("CopyProcExeTo not implemented on darwin")
}

// SetProcName set process name
// dummy implementation does nothing on darwin
func SetProcName(name string) {
}
