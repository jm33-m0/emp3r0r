//go:build !windows || !amd64

package syscall

// SyscallTable manages the resolved system calls in memory
type SyscallTable struct{}

// Caches SyscallTable for later use
var RuntimeSyscallTable *SyscallTable

func InitializeSyscallTable() (*SyscallTable, error) {
	return &SyscallTable{}, nil
}
