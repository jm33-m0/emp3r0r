//go:build windows && !(amd64 && cgo)

package syscall

import "fmt"

// invokeSyscall executes an NT syscall via a plain indirect syscall (the
// SilentMoonwalk stack-spoofing path requires windows/amd64 built with cgo).
func (table *SyscallTable) invokeSyscall(name string, args ...uintptr) (uint32, error) {
	info, found := table.GetSyscall(name)
	if !found {
		return 0, fmt.Errorf("system call %s not found in table", name)
	}
	return executeSyscall(info.SSN, table.selectGadget(), args), nil
}
