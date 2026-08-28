//go:build !windows

package syscall

// SyscallTable manages the resolved system calls in memory
type SyscallTable struct{}

// Caches SyscallTable for later use
var RuntimeSyscallTable *SyscallTable

// GetRuntimeSyscallTable returns the process-wide SyscallTable
// (non-Windows stub; never initialized).
func GetRuntimeSyscallTable() (*SyscallTable, error) {
	return RuntimeSyscallTable, nil
}

func InitializeSyscallTable() (*SyscallTable, error) {
	return &SyscallTable{}, nil
}
