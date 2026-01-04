package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/shirou/gopsutil/v3/process"
)

// ProcEntry a process entry of a process list
type ProcEntry struct {
	Name    string `json:"name" cbor:"1,keyasint"`    // process name
	Cmdline string `json:"cmdline" cbor:"2,keyasint"` // process cmdline
	Token   string `json:"token" cbor:"3,keyasint"`   // process token/username
	PID     int    `json:"pid" cbor:"4,keyasint"`     // process ID
	PPID    int    `json:"ppid" cbor:"5,keyasint"`    // parent process ID
}

// ProcessList a list of current processes with filters
func ProcessList(pid int, username, command, commandLine string) (list []ProcEntry) {
	var (
		err error
		p   ProcEntry
	)

	procs, err := process.Processes()
	if err != nil {
		logging.Debugf("ProcessList: %v", err)
		return nil
	}

	// loop through processes
	for _, proc := range procs {
		p.Cmdline, err = proc.Cmdline()
		if err != nil {
			logging.Debugf("proc cmdline: %v", err)
			p.Cmdline = "unknown_cmdline"
		}
		p.Name, err = proc.Name()
		if err != nil {
			logging.Debugf("proc name: %v", err)
			p.Name = "unknown_proc"
		}
		p.PID = int(proc.Pid)
		i, err := proc.Ppid()
		p.PPID = int(i)
		if err != nil {
			logging.Debugf("proc ppid: %v", err)
			p.PPID = 0
		}
		p.Token, err = proc.Username()
		if err != nil {
			logging.Debugf("proc token: %v", err)
			uids, err := proc.Uids()
			if err != nil {
				p.Token = "unknown_user"
			}
			for i, uid := range uids {
				p.Token += strconv.Itoa(int(uid))
				if i != len(uids)-1 {
					p.Token += ", "
				}
			}
		}

		// Apply filters
		if (pid == 0 || p.PID == pid) &&
			(username == "" || p.Token == username) &&
			(command == "" || strings.Contains(p.Name, command)) &&
			(commandLine == "" || strings.Contains(p.Cmdline, commandLine)) {
			list = append(list, p)
		}
	}
	return
}

// ProcExePath read exe path of a process
func ProcExePath(pid int) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil || proc == nil {
		logging.Debugf("No such process (%d): %v", pid, err)
		return "dead_process"
	}
	exe, err := proc.Exe()
	if err != nil {
		return fmt.Sprintf("err_%v", err)
	}
	exe = strings.Fields(exe)[0] // get rid of other stuff
	return exe
}

// ProcCwd read cwd path of a process
func ProcCwd(pid int) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil || proc == nil {
		logging.Debugf("No such process (%d): %v", pid, err)
		return "dead_process"
	}
	cwd, err := proc.Cwd()
	if err != nil {
		return fmt.Sprintf("err_%v", err)
	}
	return cwd
}

// ProcCmdline read cmdline data of a process
func ProcCmdline(pid int) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil || proc == nil {
		logging.Debugf("No such process (%d): %v", pid, err)
		return "dead_process"
	}
	cmdline, err := proc.Cmdline()
	if err != nil {
		return fmt.Sprintf("err_%v", err)
	}
	return cmdline
}

// IsPIDAlive check if a PID exists
func IsPIDAlive(pid int) (alive bool) {
	alive, err := process.PidExists(int32(pid))
	if err != nil {
		logging.Debugf("IsPIDAlive: %v", err)
		return false
	}
	return alive
}

// IsProcAlive check if a process name exists, returns its process(es)
func IsProcAlive(procName string) (alive bool, procs []*process.Process) {
	allprocs, err := process.Processes()
	if err != nil {
		logging.Println(err)
		return
	}

	for _, p := range allprocs {
		exe, err := p.Exe()
		if err != nil {
			continue
		}
		exe_name := filepath.Base(exe)
		if exe_name == procName {
			alive, _ = p.IsRunning()
			procs = append(procs, p)
		}
	}

	return
}

// PidOf PID of a process name
func PidOf(name string) []int {
	pids := make([]int, 1)
	allprocs, err := process.Processes()
	if err != nil {
		logging.Println(err)
		return pids
	}

	for _, p := range allprocs {
		if p.String() == name {
			pids = append(pids, int(p.Pid))
		}
	}

	return pids
}

// Get children processes of a process
func GetChildren(pid int) (children []int, err error) {
	d, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		logging.Debugf("GetChildren: %v", err)
		return
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
	return
}

// sleep for a random interval between 120ms to 1min
func TakeASnap() {
	interval := time.Duration(RandInt(120, 60000))
	time.Sleep(interval * time.Millisecond)
}

// sleep for a random interval between 5ms to 100ms
func TakeABlink() {
	interval := time.Duration(RandInt(5, 100))
	time.Sleep(interval * time.Millisecond)
}
