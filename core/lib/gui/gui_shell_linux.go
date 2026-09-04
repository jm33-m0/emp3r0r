//go:build linux
// +build linux

package gui

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnsureStdio guarantees fds 0/1/2 are open before the GUI binds its HTTP
// listener and later dup2s a pty onto them. If the process was started with
// stdio closed (launcher, service, nohup...), the OS would hand the first
// free fd — possibly 0/1/2 — to the listening socket; dup2-ing the pty over
// it at login would then silently kill the GUI server.
func EnsureStdio() {
	for fd := 0; fd <= 2; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			nullFd, oerr := unix.Open("/dev/null", unix.O_RDWR, 0)
			if oerr != nil {
				continue
			}
			_ = unix.Dup2(nullFd, fd)
			if nullFd > 2 {
				_ = unix.Close(nullFd)
			}
		}
	}
}

func guiDefaultShell() string {
	for _, candidate := range []string{os.Getenv("SHELL"), "/bin/bash", "/bin/sh"} {
		if candidate != "" {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	return "/bin/sh"
}

// guiSpawnShell launches the operator's login shell as a child process on a
// fresh pty. Setsid + Setctty make the pty the shell's controlling terminal,
// so job control, Ctrl+C/Z, SIGWINCH-driven resize and full-screen programs
// behave exactly like a normal terminal. The shell is a separate process on
// purpose: the emp3r0r console owns the cc process' own stdio fds (0/1/2),
// so the OS shell cannot share them.
func guiSpawnShell(id string, cols, rows uint16) (*shellSession, error) {
	if cols == 0 || rows == 0 {
		cols, rows = 120, 30
	}
	shellPath := guiDefaultShell()

	master, slave, err := guiOpenPty()
	if err != nil {
		return nil, err
	}
	_ = guiSetPtySize(master, cols, rows)

	cmd := exec.Command(shellPath)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	if home, herr := os.UserHomeDir(); herr == nil && home != "" {
		cmd.Dir = home
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0, // child fd 0 is the pty slave (cmd.Stdin)
	}
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return nil, fmt.Errorf("start %s: %v", shellPath, err)
	}
	_ = slave.Close() // only the child keeps it now

	return &shellSession{id: id, master: master, cmd: cmd}, nil
}
