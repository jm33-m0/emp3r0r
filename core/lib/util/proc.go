package util

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ProcEntry a process entry of a process list
type ProcEntry struct {
	Name    string `json:"name" cbor:"1,keyasint"`    // process name
	Cmdline string `json:"cmdline" cbor:"2,keyasint"` // process cmdline
	Token   string `json:"token" cbor:"3,keyasint"`   // process token/username
	PID     int    `json:"pid" cbor:"4,keyasint"`     // process ID
	PPID    int    `json:"ppid" cbor:"5,keyasint"`    // parent process ID
}

// ProcSimple represents basic process info for IsProcAlive
type ProcSimple struct {
	Pid int32
}

// ProcessList a list of current processes with filters
func ProcessList(pid int, username, command, commandLine string) (list []ProcEntry) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logging.Debugf("ProcessList: %v", err)
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		p := getProcEntry(pID)

		// Apply filters
		if (pid == 0 || p.PID == pid) &&
			(username == "" || p.Token == username) &&
			(command == "" || strings.Contains(p.Name, command)) &&
			(commandLine == "" || strings.Contains(p.Cmdline, commandLine)) {
			list = append(list, p)
		}
	}
	return list
}

func getProcEntry(pid int) ProcEntry {
	p := ProcEntry{
		PID:     pid,
		Cmdline: ProcCmdline(pid),
		Name:    ProcExePath(pid),
	}
	if p.Name == "dead_process" || strings.HasPrefix(p.Name, "err_") {
		// Fallback to /proc/<pid>/comm
		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err == nil {
			p.Name = strings.TrimSpace(string(commBytes))
		} else {
			p.Name = "unknown_proc"
		}
	} else {
		p.Name = filepath.Base(p.Name)
	}

	// Parse /proc/<pid>/status for PPID and UID
	statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err == nil {
		lines := strings.Split(string(statusBytes), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					p.PPID, _ = strconv.Atoi(fields[1])
				}
			} else if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uidStr := fields[1]
					u, err := user.LookupId(uidStr)
					if err == nil {
						p.Token = u.Username
					} else {
						p.Token = uidStr
					}
				}
			}
		}
	}
	if p.Token == "" {
		p.Token = "unknown_user"
	}

	return p
}

// ProcExePath read exe path of a process
func ProcExePath(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return "dead_process"
		}
		return fmt.Sprintf("err_%v", err)
	}
	fields := strings.Fields(exe)
	if len(fields) > 0 {
		return fields[0]
	}
	return exe
}

// ProcCwd read cwd path of a process
func ProcCwd(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return "dead_process"
		}
		return fmt.Sprintf("err_%v", err)
	}
	return cwd
}

// ProcCmdline read cmdline data of a process
func ProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return "dead_process"
		}
		return fmt.Sprintf("err_%v", err)
	}
	if len(data) == 0 {
		return "unknown_cmdline"
	}
	// cmdline args are null-byte separated
	args := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	strArgs := make([]string, len(args))
	for i, arg := range args {
		strArgs[i] = string(arg)
	}
	cmdline := strings.Join(strArgs, " ")
	if strings.TrimSpace(cmdline) == "" {
		return "unknown_cmdline"
	}
	return cmdline
}

// IsPIDAlive check if a PID exists
func IsPIDAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// IsProcAlive check if a process name exists, returns its process(es)
func IsProcAlive(procName string) (alive bool, procs []*ProcSimple) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logging.Errorf("IsProcAlive: %v", err)
		return false, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		exe := ProcExePath(pid)
		exeName := filepath.Base(exe)
		if exeName == "dead_process" || strings.HasPrefix(exeName, "err_") {
			commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if err == nil {
				exeName = strings.TrimSpace(string(commBytes))
			}
		}

		if exeName == procName {
			if IsPIDAlive(pid) {
				alive = true
				procs = append(procs, &ProcSimple{Pid: int32(pid)})
			}
		}
	}

	return alive, procs
}

// PidOf PID of a process name
func PidOf(name string) []int {
	pids := make([]int, 0)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logging.Errorf("PidOf: %v", err)
		return pids
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		exe := ProcExePath(pid)
		exeName := filepath.Base(exe)
		if exeName == name {
			pids = append(pids, pid)
		}
	}

	return pids
}

// Get children processes of a process
func GetChildren(pid int) (children []int, err error) {
	d, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		logging.Debugf("GetChildren: %v", err)
		return children, err
	}
	threads := make([]int, 0)
	for _, thread := range d {
		tid, err := strconv.Atoi(thread.Name())
		if err != nil {
			continue
		}
		threads = append(threads, tid)
	}
	for _, tid := range threads {
		children_file := fmt.Sprintf("/proc/%d/task/%d/children", pid, tid)
		data, err := os.ReadFile(children_file)
		if err != nil {
			logging.Debugf("GetChildren: %v", err)
			return nil, err
		}
		children_str := strings.Fields(strings.TrimSpace(string(data)))
		for _, child := range children_str {
			child_pid, err := strconv.Atoi(child)
			if err != nil {
				continue
			}
			children = append(children, child_pid)
		}
	}
	return children, err
}

// sleep for a random interval between 5s to 60s
var TakeASnap = func() {
	interval := time.Duration(RandInt(5000, 60000)) * time.Millisecond
	for {
		start := time.Now()
		time.Sleep(interval)
		elapsed := time.Since(start)
		if elapsed >= interval {
			break
		}
		// If we are here, it means the sleep was interrupted or skipped.
		// We subtract the elapsed time and try to sleep the remainder.
		logging.Debugf("TakeASnap: sleep was interrupted/skipped (%v < %v), sleeping remainder", elapsed, interval)
		interval -= elapsed
	}
}

// sleep for a random interval between 100ms to 500ms
func TakeABlink() {
	interval := time.Duration(RandInt(100, 500))
	time.Sleep(interval * time.Millisecond)
}
