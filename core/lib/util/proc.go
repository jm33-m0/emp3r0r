package util

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	gops "github.com/mitchellh/go-ps"
	"github.com/shirou/gopsutil/v3/process"
)

// ProcEntry a process entry of a process list
type ProcEntry struct {
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
}

// ProcessList a list of current processes
func ProcessList() (list []ProcEntry) {
	var (
		err error
		p   ProcEntry
	)

	procs, err := process.Processes()
	if err != nil {
		log.Printf("ProcessList: %v", err)
		return nil
	}

	// loop through processes
	for _, proc := range procs {
		p.Cmdline, err = proc.Cmdline()
		if err != nil {
			log.Printf("proc cmdline: %v", err)
			p.Cmdline = "unknown_cmdline"
		}
		p.Name, err = proc.Name()
		if err != nil {
			log.Printf("proc name: %v", err)
			p.Name = "unknown_proc"
		}
		p.PID = int(proc.Pid)
		i, err := proc.Ppid()
		p.PPID = int(i)
		if err != nil {
			log.Printf("proc ppid: %v", err)
			p.PPID = 0
		}
		p.Token, err = proc.Username()
		if err != nil {
			log.Printf("proc token: %v", err)
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

		list = append(list, p)
	}
	return
}

// ProcExePath read exe path of a process
func ProcExePath(pid int) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil || proc == nil {
		log.Printf("No such process (%d): %v", pid, err)
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
		log.Printf("No such process (%d): %v", pid, err)
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
		log.Printf("No such process (%d): %v", pid, err)
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
		log.Printf("IsPIDAlive: %v", err)
		return false
	}
	return alive
}

// IsProcAlive check if a process name exists, returns its process(es)
func IsProcAlive(procName string) (alive bool, procs []*os.Process) {
	allprocs, err := gops.Processes()
	if err != nil {
		log.Println(err)
		return
	}

	for _, p := range allprocs {
		if p.Executable() == procName {
			alive = true
			proc, err := os.FindProcess(p.Pid())
			if err != nil {
				log.Println(err)
			}
			procs = append(procs, proc)
		}
	}

	return
}

// PidOf PID of a process name
func PidOf(name string) []int {
	pids := make([]int, 1)
	allprocs, err := gops.Processes()
	if err != nil {
		log.Println(err)
		return pids
	}

	for _, p := range allprocs {
		if p.Executable() == name {
			proc, err := os.FindProcess(p.Pid())
			if err != nil {
				log.Println(err)
			}
			pids = append(pids, proc.Pid)
		}
	}

	return pids
}

// Get children processes of a process
func GetChildren(pid int) (children []int, err error) {
	d, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		log.Printf("GetChildren: %v", err)
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
			log.Printf("GetChildren: %v", err)
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
