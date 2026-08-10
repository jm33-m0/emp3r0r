//go:build !windows

package priv

import (
	"errors"

	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
)

type Handle uintptr

var errNotSupported = errors.New("privilege manipulation not supported on non-windows platforms")

// StealToken stub for non-windows platforms
func StealToken(table *syscall.SyscallTable, targetPID uint32, hExistingToken ...Handle) (Handle, error) {
	return 0, errNotSupported
}

// ExecuteAsToken stub for non-windows platforms
func ExecuteAsToken(hImpersonationToken Handle, action func() error) error {
	return errNotSupported
}

// DuplicateSystemToken stub for non-windows platforms
func DuplicateSystemToken(table *syscall.SyscallTable, hProcessToken Handle) (Handle, error) {
	return 0, errNotSupported
}

// GetTokenUserSid stub for non-windows platforms
func GetTokenUserSid(hToken Handle) (string, error) {
	return "", errNotSupported
}

// GetTokenIntegrityLevel stub for non-windows platforms
func GetTokenIntegrityLevel(hToken Handle) (string, error) {
	return "", errNotSupported
}

// GetTokenPrivileges stub for non-windows platforms
func GetTokenPrivileges(hToken Handle) ([]string, error) {
	return nil, errNotSupported
}

// Whoami stub for non-windows platforms
func Whoami() (string, error) {
	return "", errNotSupported
}
