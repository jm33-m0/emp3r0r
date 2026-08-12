//go:build !windows

package coffloader

import (
	"fmt"
	"runtime"
)

// RunWindowsCOFF returns an error on non-Windows systems.
func RunWindowsCOFF(_ []byte, _ string, _ []CoffArg, _ uintptr) (string, error) {
	return "", fmt.Errorf("RunWindowsCOFF is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
