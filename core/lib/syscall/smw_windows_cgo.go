//go:build windows && amd64 && cgo

package syscall

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/syscall/smw"
)

// invokeSyscall executes an NT syscall with SilentMoonwalk call-stack
// spoofing: the SMW C wrapper synthesizes fake unwind frames and jumps to a
// ntdll "syscall; ret" gadget with EAX=SSN. Syscalls with more than 8
// arguments (e.g. NtCreateUserProcess) or a failed SMW initialization
// degrade to a plain indirect syscall.
func (table *SyscallTable) invokeSyscall(name string, args ...uintptr) (uint32, error) {
	info, found := table.GetSyscall(name)
	if !found {
		return 0, fmt.Errorf("system call %s not found in table", name)
	}
	if len(args) > 8 {
		return executeSyscall(info.SSN, table.selectGadget(), args), nil
	}

	status, err := smw.Call(info.SSN, table.selectGadget(), args)
	if err != nil {
		return executeSyscall(info.SSN, table.selectGadget(), args), nil
	}
	return status, nil
}
