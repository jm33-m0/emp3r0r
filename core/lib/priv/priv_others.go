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

// MakeToken stub for non-windows platforms
func MakeToken(user, domain, password string) (*LogonSession, error) {
	return nil, errNotSupported
}

// GetTokenLogonID stub for non-windows platforms
//
// Signatures intentionally mirror the Windows implementations at the type
// level (Handle ≈ windows.Handle, uint64 ≈ windows.LUID rendered via
// luidToUint64), but cannot name x/sys/windows types since that package does
// not build on non-Windows targets.
func GetTokenLogonID(hToken Handle) (uint64, error) {
	return 0, errNotSupported
}

// ImportTicket stub for non-windows platforms
func ImportTicket(session *LogonSession, kirbi []byte) error {
	return errNotSupported
}

// ImportTicketBase64 stub for non-windows platforms
func ImportTicketBase64(session *LogonSession, ticketB64 string) error {
	return errNotSupported
}

// ImportTicketWithToken stub for non-windows platforms
func ImportTicketWithToken(hToken Handle, ticketB64 string) error {
	return errNotSupported
}

// ImportTicketToLUID stub for non-windows platforms
func ImportTicketToLUID(luid uint64, kirbi []byte) error {
	return errNotSupported
}

// ImportTicketToLUIDBase64 stub for non-windows platforms
func ImportTicketToLUIDBase64(luid uint64, ticketB64 string) error {
	return errNotSupported
}
