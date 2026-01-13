//go:build windows
// +build windows

package coffloader

import (
	"fmt"

	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

// RunWindowsCOFF executes a COFF/BOF payload using goffloader on Windows.
// Export is accepted for parity, but goffloader determines the entry from the object itself.
func RunWindowsCOFF(payload []byte, _ string, args []CoffArg) (out string, err error) {
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

	packed, err := lighthouse.PackArgs(packedArgs)
	if err != nil {
		return "", fmt.Errorf("packing BOF args: %w", err)
	}

	output, err := coff.Load(payload, packed)
	if err != nil {
		return "", fmt.Errorf("executing COFF module: %w", err)
	}

	return output, nil
}
