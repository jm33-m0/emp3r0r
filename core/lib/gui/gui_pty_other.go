//go:build !linux
// +build !linux

package gui

import (
	"errors"
	"os"
)

// The cc GUI (and the emp3r0r operator console in general) only runs on
// Linux. These stubs keep the package compiling on other platforms.

type termSize struct {
	Cols uint16
	Rows uint16
}

func guiOpenPty() (*os.File, *os.File, error) {
	return nil, nil, errors.New("emp3r0r GUI requires Linux")
}

func guiSetPtySize(master *os.File, cols, rows uint16) error {
	return errors.New("emp3r0r GUI requires Linux")
}

func guiAttachPty(slave *os.File) error {
	return errors.New("emp3r0r GUI requires Linux")
}
