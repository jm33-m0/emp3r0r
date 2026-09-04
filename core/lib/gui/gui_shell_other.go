//go:build !linux
// +build !linux

package gui

import (
	"errors"
)

// The OS shell (like the whole cc GUI) only runs on Linux.

func guiSpawnShell(id string, cols, rows uint16) (*shellSession, error) {
	return nil, errors.New("OS shell requires Linux")
}

// EnsureStdio is a no-op on non-Linux platforms (the GUI does not run
// there anyway).
func EnsureStdio() {}
