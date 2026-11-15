//go:build linux

package operator

import (
	"os/exec"
	"syscall"
)

// detachWorker puts the loop worker in its own session so it does not share a
// controlling terminal or session signals with the operator console.
func detachWorker(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
