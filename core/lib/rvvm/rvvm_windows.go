//go:build windows

package rvvm

import (
	"errors"
	"runtime"
	"syscall"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

// The interpreter DLL uses the platform calling convention. syscall.SyscallN
// provides the native call trampoline; only 64-bit Windows is supported (the
// 32-bit trampoline uses stdcall, while the DLL exports use cdecl).
func checkPlatform() error {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return nil
	default:
		return errors.New("RISC-V BOFs on Windows require amd64 or arm64")
	}
}

func callRun(module *memmod.Module, args ...uintptr) (uintptr, error) {
	addr, err := module.ProcAddressByName("rv_run")
	if err != nil || addr == 0 {
		return 0, errors.New("rv_run export not found")
	}
	r1, _, _ := syscall.SyscallN(addr, args...)
	return r1, nil
}

func callLastError(module *memmod.Module) string {
	addr, err := module.ProcAddressByName("rv_last_error")
	if err != nil || addr == 0 {
		return ""
	}
	r1, _, _ := syscall.SyscallN(addr)
	if r1 == 0 {
		return ""
	}
	return readCString(r1)
}

func callFree(module *memmod.Module, ptr uintptr) {
	addr, err := module.ProcAddressByName("rv_free")
	if err != nil || addr == 0 {
		return
	}
	_, _, _ = syscall.SyscallN(addr, ptr)
}
