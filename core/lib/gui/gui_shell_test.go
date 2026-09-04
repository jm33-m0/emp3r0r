//go:build linux
// +build linux

package gui

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

// TestGuiSpawnShell launches the OS shell (as the GUI does) and drives it
// through its pty: type a command, read the output back, exit.
func TestGuiSpawnShell(t *testing.T) {
	sess, err := guiSpawnShell("test", 100, 30)
	if err != nil {
		t.Fatalf("guiSpawnShell: %v", err)
	}
	defer sess.close()

	if _, err := sess.master.Write([]byte("echo gui-shell-ok-99; exit\n")); err != nil {
		t.Fatalf("write to shell: %v", err)
	}

	reader := bufio.NewReader(sess.master)
	deadline := time.After(20 * time.Second)
	var saw strings.Builder
	for {
		line, rerr := reader.ReadString('\n')
		saw.WriteString(line)
		if strings.Contains(saw.String(), "gui-shell-ok-99") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for shell output, got so far: %q", saw.String())
		default:
		}
		if rerr != nil {
			t.Fatalf("pty read ended early: %v (got %q)", rerr, saw.String())
		}
	}
}
