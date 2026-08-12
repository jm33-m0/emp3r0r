//go:build !linux || !cgo

package coffloader

import (
	"fmt"
	"runtime"
)

// RunLinuxCOFF returns an error on systems that do not support Linux CGO BOF execution.
func RunLinuxCOFF(_ []byte, _ string, _ []CoffArg, _ uintptr) (string, error) {
	return "", fmt.Errorf("RunLinuxCOFF is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
