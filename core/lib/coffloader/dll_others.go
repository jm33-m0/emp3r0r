//go:build !windows

package coffloader

import "fmt"

// RunWindowsCOFFViaDLL is Windows-only.
func RunWindowsCOFFViaDLL(_, _ []byte, _ string, _ []CoffArg, _ uintptr) (string, error) {
	return "", fmt.Errorf("in-memory DLL COFF loading is only supported on Windows")
}
