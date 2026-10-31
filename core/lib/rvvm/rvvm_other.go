//go:build !linux && !windows

package rvvm

import (
	"errors"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

func checkPlatform() error {
	return errors.New("RISC-V BOFs are supported on Linux and Windows only")
}

func callRun(*memmod.Module, ...uintptr) (uintptr, error) {
	return 0, errors.New("RISC-V BOFs are supported on Linux and Windows only")
}

func callLastError(*memmod.Module) string { return "" }

func callFree(*memmod.Module, uintptr) {}
