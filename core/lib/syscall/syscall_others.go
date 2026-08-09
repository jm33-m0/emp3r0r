//go:build !windows

package syscall

// SyscallTable manages the resolved system calls in memory
type SyscallTable struct{}

// Caches SyscallTable for later use
var RuntimeSyscallTable *SyscallTable

func InitializeSyscallTable() (*SyscallTable, error) {
	return &SyscallTable{}, nil
}
