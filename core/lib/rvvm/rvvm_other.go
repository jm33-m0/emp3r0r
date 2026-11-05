//go:build !linux

package rvvm

import (
	"errors"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

var errUnsupported = errors.New("rv modules run on Linux agents only")

func checkPlatform() error { return errUnsupported }

func callRun(*memmod.Module, ...uintptr) (uintptr, error) {
	return 0, errUnsupported
}

func callLastError(*memmod.Module) string { return "" }

func callFree(*memmod.Module, uintptr) {}
