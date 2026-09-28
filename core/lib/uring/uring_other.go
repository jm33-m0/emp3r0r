//go:build !linux || (!386 && !amd64 && !arm && !arm64) || no_uring

// Package uring exposes the same io_uring file helpers on platforms without
// the raw Linux io_uring path, and on builds made with `-tags no_uring`; they
// delegate to package os so callers stay portable and no runtime switch is
// needed.
package uring

import (
	"os"
)

// ReadFile reads name, falling back to package os.
func ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

// WriteFile writes data to name with perm, falling back to package os.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

// AppendFile appends data to name, falling back to package os.
func AppendFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
