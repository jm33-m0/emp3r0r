//go:build linux
// +build linux

package util

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

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
			(username == "" || p.Token == username || p.UID == username) &&
			(command == "" || strings.Contains(p.Name, command)) &&
			(commandLine == "" || strings.Contains(p.Cmdline, commandLine)) {
			list = append(list, p)
		}
	}
	return list
}

func getProcEntry(pid int) ProcEntry {
	p := ProcEntry{
		PID:       pid,
		Namespace: "N/A",
	}

	// Read /proc/<pid>/comm for process name
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		p.Name = strings.TrimSpace(string(commBytes))
	} else {
		p.Name = "unknown_proc"
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
					p.UID = fields[1]
					u, err := user.LookupId(p.UID)
					if err == nil {
						p.Token = u.Username
					} else {
						p.Token = p.UID
					}
				}
			}
		}
	}
	if p.Token == "" {
		p.Token = "unknown_user"
	}
	if p.UID == "" {
		p.UID = "N/A"
	}

	// Read FS (mount) namespace from /proc/<pid>/ns/mnt
	nsLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err == nil && nsLink != "" {
		p.Namespace = nsLink
	}

	return p
}

// ProcExePath read comm of a process
func ProcExePath(pid int) string {
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return "dead_process"
		}
		return fmt.Sprintf("err_%v", err)
	}
	return strings.TrimSpace(string(commBytes))
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
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
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

		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(commBytes))

		if name == procName {
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

		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		procName := strings.TrimSpace(string(commBytes))

		if procName == name {
			pids = append(pids, pid)
		}
	}

	return pids
}

// GetChildren get children processes of a process
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
