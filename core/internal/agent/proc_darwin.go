//go:build darwin
// +build darwin

package agent

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

func crossPlatformSetProcName(name string) {
	// dummy implementation does nothing on darwin
}
