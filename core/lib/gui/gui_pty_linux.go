//go:build linux
// +build linux

package gui

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// termSize mirrors the terminal dimensions the browser reports.
type termSize struct {
	Cols uint16
	Rows uint16
}

// guiOpenPty allocates a new pseudo-terminal pair by hand (x/sys no longer
// ships a Linux Openpty helper): open /dev/ptmx, unlock it, then open the
// resulting /dev/pts/N slave. The console (reeflective readline) runs with
// the slave as its stdin/stdout/stderr, while the GUI frontend is bridged to
// the master end over a websocket. This gives the browser a real, line
// discipline-enabled terminal: arrows, tab completion, Ctrl+C, history,
// syntax highlighting and the cobra help renderer all work exactly like they
// do in the tmux CLI.
func guiOpenPty() (master, slave *os.File, err error) {
	masterFd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %v", err)
	}
	master = os.NewFile(uintptr(masterFd), "pty-master")

	// unlockpt: allow the slave to be opened
	if err := unix.IoctlSetPointerInt(masterFd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("unlockpt: %v", err)
	}
	// ptsname: find the slave number
	n, err := unix.IoctlGetInt(masterFd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("TIOCGPTN: %v", err)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", n)
	slaveFd, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("open %s: %v", slavePath, err)
	}
	slave = os.NewFile(uintptr(slaveFd), "pty-slave")
	return master, slave, nil
}

// guiSetPtySize applies the given terminal size to the pty master. The pty
// driver propagates it to the slave, which is what readline queries when it
// redraws, so resizing the browser terminal reflows the console correctly.
func guiSetPtySize(master *os.File, cols, rows uint16) error {
	if master == nil {
		return fmt.Errorf("no pty")
	}
	return unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{
		Row: rows,
		Col: cols,
	})
}

// guiAttachPty makes the pty slave the process' standard input/output/error.
// The cc process is dedicated to the operator session, so nothing else needs
// the original descriptors. The reeflective console reads os.Stdin and writes
// os.Stdout, so this is what funnels the interactive console into the pty.
func guiAttachPty(slave *os.File) error {
	if slave == nil {
		return fmt.Errorf("no pty slave")
	}
	fd := int(slave.Fd())
	for _, target := range []int{0, 1, 2} {
		if err := unix.Dup2(fd, target); err != nil {
			return fmt.Errorf("dup2 %d -> %d: %v", fd, target, err)
		}
	}
	return nil
}
