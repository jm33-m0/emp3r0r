//go:build linux
// +build linux

package gui

import (
	"bufio"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestGuiPtyOpen exercises the hand-rolled openpty: open /dev/ptmx, unlock,
// open the slave, resize the winsize and confirm a child process can talk
// through the pair (the GUI console relies on exactly this).
func TestGuiPtyOpen(t *testing.T) {
	master, slave, err := guiOpenPty()
	if err != nil {
		t.Fatalf("guiOpenPty: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	// the console's readline queries the terminal size on the slave; make
	// sure TIOCSWINSZ on the master is accepted
	if err := guiSetPtySize(master, 100, 30); err != nil {
		t.Fatalf("guiSetPtySize: %v", err)
	}

	cmd := exec.Command("/bin/sh", "-c", "echo pty-ok-$((40+2))")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sh: %v", err)
	}

	// read from the master until the child's output arrives
	reader := bufio.NewReader(master)
	deadline := time.After(10 * time.Second)
	for {
		line, rerr := reader.ReadString('\n')
		if rerr == nil && strings.Contains(line, "pty-ok-42") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for pty output, got: %q", line)
		default:
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("sh exited with error: %v", err)
	}
}
