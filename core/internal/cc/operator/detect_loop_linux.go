//go:build linux

package operator

import (
	"os/exec"
	"syscall"
)

// detachWorker puts the loop worker in its own session so it survives the
// operator console and its tmux session.
func detachWorker(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
