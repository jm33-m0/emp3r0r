//go:build !windows

package coffloader

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
)

// RunWindowsCOFFViaDLL is Windows-only.
func RunWindowsCOFFViaDLL(_, _ []byte, _ string, _ []CoffArg, _ uintptr) (string, error) {
	return "", fmt.Errorf("in-memory DLL COFF loading is only supported on Windows")
}

// RunCOFFDependency is Windows-only.
func RunCOFFDependency(_ []byte, _ string, _ []CoffArg, _ uintptr, _ ...memdeps.UseOption) (string, error) {
	return "", fmt.Errorf("in-memory DLL COFF loading is only supported on Windows")
}
