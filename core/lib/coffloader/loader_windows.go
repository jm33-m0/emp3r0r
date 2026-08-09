//go:build windows
// +build windows

package coffloader

import (
	"fmt"
)

// RunWindowsCOFF executes a COFF/BOF payload using goffloader on Windows.
// Export is accepted for parity, but goffloader determines the entry from the object itself.
// If token is non-zero the BOF entry point runs under impersonation via PreExecHook / PostExecHook.
func RunWindowsCOFF(payload []byte, _ string, args []CoffArg, token uintptr) (out string, err error) {
	// Publish token so invokeMethod's goroutine can read it.
	activeTokenMu.Lock()
	activeToken = token
	activeTokenMu.Unlock()
	defer func() {
		activeTokenMu.Lock()
		activeToken = 0
		activeTokenMu.Unlock()
	}()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("coff loader panic: %v", r)
			out = ""
		}
	}()

	packedArgs, err := PackCoffArgs(args)
	if err != nil {
		return "", err
	}

	packed, err := LighthousePackArgs(packedArgs)
	if err != nil {
		return "", fmt.Errorf("packing BOF args: %w", err)
	}

	output, err := CoffLoad(payload, packed)
	if err != nil {
		return "", fmt.Errorf("executing COFF module: %w", err)
	}

	return output, nil
}
