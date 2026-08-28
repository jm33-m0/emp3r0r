//go:build windows

// Command smwtool verifies the SilentMoonwalk + indirect-syscall integration
// in lib/syscall.
//
// What it exercises:
//
//  1. ntdll SSN resolution (table sort vs stub-byte extraction)
//  2. syscall gadget discovery + rotation pool size
//  3. real spoofed syscalls through the SilentMoonwalk desync path
//     (cgo builds) — NtOpenProcess, NtOpenProcessToken, 4-arg
//     NtQuerySystemInformation with a parsed process list, and 5/6-arg
//     virtual-memory syscalls
//  4. repeated calls (gadget rotation stability)
//  5. the pure-Go fallback (non-cgo builds) producing identical results
//
// Build (from core/; nasm in PATH for the SMW core):
//
//	# regenerate desyncspoofer.syso if needed
//	go generate ./lib/syscall/smw
//
//	# SMW spoofed path (cgo):
//	CGO_ENABLED=1 go build -o smwtool.exe ./cmd/smwtool
//
//	# fallback path (pure Go):
//	CGO_ENABLED=0 go build -o smwtool.exe ./cmd/smwtool
//
// Cross-build on Linux with mingw/zig:
//
//	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o smwtool.exe ./cmd/smwtool
package main

import (
	"fmt"
	"os"
	"unicode/utf16"
	"unsafe"

	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall/smw"
	"golang.org/x/sys/windows"
)

const (
	statusSuccess             = 0x00000000
	statusInfoLengthMismatch  = 0xC0000004
	systemProcessInformation  = 5
	processQueryLimitedAccess = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
)

var failures int

func check(label string, status uint32, err error) {
	if err != nil {
		failures++
		fmt.Printf("  [FAIL] %-42s err=%v\n", label, err)
		return
	}
	if status != statusSuccess {
		failures++
		fmt.Printf("  [FAIL] %-42s status=0x%08X\n", label, status)
		return
	}
	fmt.Printf("  [ OK ] %s\n", label)
}

func main() {
	fmt.Println("=== emp3r0r syscall + SilentMoonwalk test ===")

	// ── 1. Table initialization ────────────────────────────────────────────
	table, err := ntsyscall.InitializeSyscallTable()
	if err != nil {
		fmt.Printf("[FAIL] InitializeSyscallTable: %v\n", err)
		os.Exit(1)
	}

	ntdllBase := ntsyscall.GetModuleBaseAddress("ntdll.dll")
	fmt.Printf("\n[1] ntdll base:           0x%X\n", ntdllBase)
	fmt.Printf("    gadgets in rotation:  %d\n", table.GadgetCount())

	// ── 2. SSN resolution vs stub-byte extraction ──────────────────────────
	fmt.Println("\n[2] SSN resolution (table sort vs stub-byte extraction):")
	for _, name := range []string{"NtOpenProcess", "NtOpenProcessToken", "NtQuerySystemInformation", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"} {
		info, found := table.GetSyscall(name)
		if !found {
			failures++
			fmt.Printf("  [FAIL] %-26s not in table\n", name)
			continue
		}
		mismatch := "match"
		if addr := ntsyscall.GetCustomProcAddress(ntdllBase, name); addr != 0 {
			if stubSSN, err := ntsyscall.ExtractSSN(addr); err == nil && stubSSN != info.SSN {
				mismatch = fmt.Sprintf("MISMATCH (stub says %d)", stubSSN)
				failures++
			}
		}
		fmt.Printf("  [ OK ] %-26s SSN=%-3d default gadget=0x%X (%s)\n", name, info.SSN, info.GadgetAddr, mismatch)
	}

	// ── 3. SMW path status ─────────────────────────────────────────────────
	fmt.Println("\n[3] SilentMoonwalk stack spoofing:")
	if smw.Ready() {
		fmt.Println("  [ OK ] ENABLED (cgo build) — InvokeSyscall routes through spoof_call")
	} else {
		fmt.Println("  [ OK ] DISABLED (pure-Go build) — InvokeSyscall uses plain indirect syscalls")
	}

	// ── 4. Spoofed token/process syscalls ──────────────────────────────────
	fmt.Println("\n[4] Spoofed syscalls:")
	pid := uint32(windows.GetCurrentProcessId())

	hProcess, status, err := ntsyscall.NtOpenProcess(table, processQueryLimitedAccess, pid)
	check(fmt.Sprintf("NtOpenProcess(pid=%d) -> 0x%X", pid, uintptr(hProcess)), status, err)
	if status == statusSuccess && hProcess != 0 {
		hToken, status, err := ntsyscall.NtOpenProcessToken(table, hProcess, windows.TOKEN_QUERY)
		check(fmt.Sprintf("NtOpenProcessToken -> 0x%X", uintptr(hToken)), status, err)
		if status == statusSuccess && hToken != 0 {
			windows.CloseHandle(hToken)
		}
		windows.CloseHandle(hProcess)
	}

	// ── 5. 4-arg syscall with real data (process list) ─────────────────────
	fmt.Println("\n[5] NtQuerySystemInformation(SystemProcessInformation) [4 args]:")
	var retLen uint32
	status, err = table.InvokeSyscall("NtQuerySystemInformation",
		uintptr(systemProcessInformation), 0, 0, uintptr(unsafe.Pointer(&retLen)))
	if status != statusInfoLengthMismatch {
		check("probe (expect STATUS_INFO_LENGTH_MISMATCH)", status, err)
	}
	fmt.Printf("    required buffer size: %d bytes\n", retLen)

	buf := make([]byte, retLen+1024)
	status, err = table.InvokeSyscall("NtQuerySystemInformation",
		uintptr(systemProcessInformation),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)))
	check(fmt.Sprintf("query (got %d bytes, %d processes)", retLen, countProcesses(buf)), status, err)

	// ── 6. 5/6-arg virtual-memory syscalls ─────────────────────────────────
	fmt.Println("\n[6] Virtual memory syscalls (5/6 args):")
	var base uintptr
	var regionSize uintptr = 4096
	status, err = ntsyscall.NtAllocateVirtualMemory(table, windows.CurrentProcess(), &base, 0, &regionSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	check(fmt.Sprintf("NtAllocateVirtualMemory -> 0x%X", base), status, err)

	if status == statusSuccess && base != 0 {
		var oldProtect uint32
		status, err = ntsyscall.NtProtectVirtualMemory(table, windows.CurrentProcess(), &base, &regionSize, windows.PAGE_EXECUTE_READ, &oldProtect)
		check("NtProtectVirtualMemory(RW -> RX)", status, err)
		ntsyscall.NtFreeVirtualMemory(table, windows.CurrentProcess(), &base, &regionSize, windows.MEM_RELEASE)
	}

	// ── 7. Gadget rotation stability ───────────────────────────────────────
	fmt.Println("\n[7] Gadget rotation (20x NtOpenProcess, random gadget per call):")
	ok := 0
	for i := 0; i < 20; i++ {
		h, status, err := ntsyscall.NtOpenProcess(table, processQueryLimitedAccess, pid)
		if status == statusSuccess && h != 0 {
			ok++
			windows.CloseHandle(h)
		} else {
			fmt.Printf("    iteration %d failed: status=0x%08X err=%v\n", i, status, err)
		}
	}
	if ok != 20 {
		failures++
	}
	fmt.Printf("    %d/20 succeeded\n", ok)

	// ── 8. Direct smw.Call (bypasses InvokeSyscall) ────────────────────────
	fmt.Println("\n[8] Direct smw.Call(ssn, gadget, args):")
	if smw.Ready() {
		info, _ := table.GetSyscall("NtOpenProcess")
		var h windows.Handle
		var clientID struct {
			UniqueProcess windows.Handle
			UniqueThread  windows.Handle
		}
		clientID.UniqueProcess = windows.Handle(pid)
		oa := struct {
			Length                   uint32
			RootDirectory            uintptr
			ObjectName               uintptr
			Attributes               uint32
			SecurityDescriptor       uintptr
			SecurityQualityOfService uintptr
		}{Length: 48}
		status, err := smw.Call(info.SSN, info.GadgetAddr, []uintptr{
			uintptr(unsafe.Pointer(&h)),
			uintptr(processQueryLimitedAccess),
			uintptr(unsafe.Pointer(&oa)),
			uintptr(unsafe.Pointer(&clientID)),
		})
		check(fmt.Sprintf("smw.Call(NtOpenProcess) -> 0x%X", uintptr(h)), status, err)
		if status == statusSuccess && h != 0 {
			windows.CloseHandle(h)
		}

		// 9-arg rejection guard
		_, err = smw.Call(info.SSN, info.GadgetAddr, make([]uintptr, 9))
		if err == nil {
			failures++
			fmt.Println("  [FAIL] smw.Call accepted 9 arguments")
		} else {
			fmt.Printf("  [ OK ] smw.Call rejects >8 args: %v\n", err)
		}
	} else {
		fmt.Println("  [SKIP] not available in pure-Go build")
	}

	// ── Summary ────────────────────────────────────────────────────────────
	fmt.Println("\n=== result ===")
	if failures == 0 {
		fmt.Println("ALL CHECKS PASSED")
	} else {
		fmt.Printf("%d CHECK(S) FAILED\n", failures)
		os.Exit(1)
	}
}

// countProcesses walks the SYSTEM_PROCESS_INFORMATION linked list returned by
// NtQuerySystemInformation and prints each process name + PID.
func countProcesses(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	count := 0
	off := uintptr(0)
	for {
		p := uintptr(unsafe.Pointer(&buf[0])) + off
		next := *(*uint32)(unsafe.Pointer(p))
		nameLen := *(*uint16)(unsafe.Pointer(p + 0x38))  // ImageName.Length
		namePtr := *(*uintptr)(unsafe.Pointer(p + 0x40)) // ImageName.Buffer
		pid := *(*uintptr)(unsafe.Pointer(p + 0x50))     // UniqueProcessId
		count++
		if nameLen > 0 && namePtr != 0 {
			chars := unsafe.Slice((*uint16)(unsafe.Pointer(namePtr)), int(nameLen)/2)
			fmt.Printf("    pid=%-8d %s\n", pid, string(utf16.Decode(chars)))
		} else {
			fmt.Printf("    pid=%-8d (System/Idle)\n", pid)
		}
		if next == 0 {
			break
		}
		off += uintptr(next)
	}
	return count
}
