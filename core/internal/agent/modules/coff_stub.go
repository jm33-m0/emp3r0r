//go:build !windows

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func runCOFFModule(_ []byte, _ def.ResolvedInvocation) (string, error) {
	return "", fmt.Errorf("COFF modules are only supported on Windows agents")
}
