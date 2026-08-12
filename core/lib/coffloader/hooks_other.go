//go:build !windows

package coffloader

import (
	"fmt"
	"runtime"
)

var (
	PreExecHook  func(token uintptr)
	PostExecHook func()
)

// CoffLoad returns an error on non-Windows platforms.
func CoffLoad(_ []byte, _ []byte) (string, error) {
	return "", fmt.Errorf("CoffLoad is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}

// LoadWithMethod returns an error on non-Windows platforms.
func LoadWithMethod(_ []byte, _ []byte, _ string) (string, error) {
	return "", fmt.Errorf("LoadWithMethod is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
