//go:build linux

package rvvm

import (
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

func checkPlatform() error { return nil }

func callRun(module *memmod.Module, args ...uintptr) (uintptr, error) {
	return module.CallExportWithArgs("Run", args...)
}

func callLastError(module *memmod.Module) string {
	ptr, err := module.CallExportWithArgs("LastError")
	if err != nil || ptr == 0 {
		return ""
	}
	return readCString(ptr)
}

func callFree(module *memmod.Module, ptr uintptr) {
	_, _ = module.CallExportWithArgs("Free", ptr)
}
