//go:build !amd64 && linux
// +build !amd64,linux

package modules

import (
	"fmt"
	"runtime"
)

func ShellcodeInjector(shellcode *string, pid int) error {
	return fmt.Errorf("unsupported platform %s", runtime.GOARCH)
}
