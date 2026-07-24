package util

import (
	"os"
	"testing"
)

func TestProcCurrent(t *testing.T) {
	pid := os.Getpid()
	if !IsPIDAlive(pid) {
		t.Fatalf("IsPIDAlive(%d) returned false for current process", pid)
	}

	cmdline := ProcCmdline(pid)
	if cmdline == "dead_process" || cmdline == "" {
		t.Errorf("ProcCmdline(%d) returned unexpected result: %s", pid, cmdline)
	}

	exe := ProcExePath(pid)
	if exe == "dead_process" || exe == "" {
		t.Errorf("ProcExePath(%d) returned unexpected result: %s", pid, exe)
	}

	procs := ProcessList(pid, "", "", "")
	if len(procs) == 0 {
		t.Errorf("ProcessList(%d) returned empty list", pid)
	} else {
		p := procs[0]
		if p.PID != pid {
			t.Errorf("ProcessList(%d) returned PID %d", pid, p.PID)
		}
		if p.Cmdline == "" || p.Cmdline == "N/A" {
			t.Errorf("ProcessList(%d) returned empty or N/A cmdline: %s", pid, p.Cmdline)
		}
		t.Logf("Current proc entry: PID=%d, Name=%s, User=%s, UID=%s, NS=%s, Cmdline=%s",
			p.PID, p.Name, p.Token, p.UID, p.Namespace, p.Cmdline)
	}
}
