//go:build windows

package syscall

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func unsafePointer(addr uintptr) unsafe.Pointer {
	return unsafe.Pointer(addr)
}

func TestGetPEBAddress(t *testing.T) {
	pebAddr := getPEBAddress()
	if pebAddr == 0 {
		t.Fatalf("getPEBAddress() returned 0")
	}
	t.Logf("PEB Address: 0x%x", pebAddr)
}

func TestGetModuleBaseAddress(t *testing.T) {
	ntdllBase := GetModuleBaseAddress("ntdll.dll")
	if ntdllBase == 0 {
		t.Fatalf("GetModuleBaseAddress(\"ntdll.dll\") returned 0")
	}
	t.Logf("ntdll.dll Base: 0x%x", ntdllBase)

	dosHeader := (*IMAGE_DOS_HEADER)(unsafePointer(ntdllBase))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		t.Fatalf("ntdll DOS header magic mismatch: got 0x%x, expected 0x5A4D", dosHeader.E_magic)
	}

	kernel32Base := GetModuleBaseAddress("kernel32.dll")
	if kernel32Base == 0 {
		t.Fatalf("GetModuleBaseAddress(\"kernel32.dll\") returned 0")
	}
	t.Logf("kernel32.dll Base: 0x%x", kernel32Base)

	nonExistentBase := GetModuleBaseAddress("nonexistent_module_12345.dll")
	if nonExistentBase != 0 {
		t.Fatalf("GetModuleBaseAddress for nonexistent module expected 0, got 0x%x", nonExistentBase)
	}
}

func TestGetCustomProcAddress(t *testing.T) {
	ntdllBase := GetModuleBaseAddress("ntdll.dll")
	if ntdllBase == 0 {
		t.Fatalf("ntdll.dll base not found")
	}

	addrCustom := GetCustomProcAddress(ntdllBase, "NtOpenProcess")
	if addrCustom == 0 {
		t.Fatalf("GetCustomProcAddress(\"NtOpenProcess\") returned 0")
	}
	t.Logf("NtOpenProcess custom resolved address: 0x%x", addrCustom)

	hNtdll, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		t.Fatalf("LoadLibrary(\"ntdll.dll\") failed: %v", err)
	}
	defer windows.FreeLibrary(hNtdll)

	addrWin, err := windows.GetProcAddress(hNtdll, "NtOpenProcess")
	if err != nil {
		t.Fatalf("GetProcAddress(\"NtOpenProcess\") failed: %v", err)
	}

	if addrCustom != uintptr(addrWin) {
		t.Errorf("Address mismatch for NtOpenProcess: custom=0x%x, win=0x%x", addrCustom, addrWin)
	}
}

func TestExtractSSN(t *testing.T) {
	ntdllBase := GetModuleBaseAddress("ntdll.dll")
	if ntdllBase == 0 {
		t.Fatalf("ntdll.dll base not found")
	}

	funcVA := GetCustomProcAddress(ntdllBase, "NtOpenProcess")
	if funcVA == 0 {
		t.Fatalf("NtOpenProcess procedure address not found")
	}

	ssn, err := ExtractSSN(funcVA)
	if err != nil {
		t.Fatalf("ExtractSSN failed for NtOpenProcess: %v", err)
	}
	t.Logf("NtOpenProcess SSN: %d (0x%X)", ssn, ssn)
}

func TestInitializeSyscallTable(t *testing.T) {
	table, err := InitializeSyscallTable()
	if err != nil {
		t.Fatalf("InitializeSyscallTable failed: %v", err)
	}

	info, found := table.GetSyscall("NtOpenProcess")
	if !found {
		t.Fatalf("NtOpenProcess not found in SyscallTable")
	}
	t.Logf("NtOpenProcess resolved: SSN=%d, Gadget=0x%x", info.SSN, info.GadgetAddr)

	if info.GadgetAddr == 0 {
		t.Errorf("GadgetAddr is 0")
	}
}

func TestGadgetRotation(t *testing.T) {
	table, err := InitializeSyscallTable()
	if err != nil {
		t.Fatalf("InitializeSyscallTable failed: %v", err)
	}

	if len(table.gadgets) == 0 {
		t.Fatalf("no syscall gadgets discovered")
	}
	t.Logf("discovered %d syscall gadgets", len(table.gadgets))

	seen := make(map[uintptr]bool)
	for _, g := range table.gadgets {
		if g == 0 {
			t.Errorf("gadget address is 0")
		}
		if seen[g] {
			t.Errorf("duplicate gadget address 0x%x", g)
		}
		seen[g] = true
	}

	// Every gadget must lie inside an executable section of ntdll.
	ranges := executableRanges(ntdllBaseOf(t))
	for _, g := range table.gadgets {
		if !addrInRanges(g, ranges) {
			t.Errorf("gadget 0x%x outside executable sections", g)
		}
	}

	info, found := table.GetSyscall("NtOpenProcess")
	if !found {
		t.Fatalf("NtOpenProcess not found in SyscallTable")
	}
	if info.GadgetAddr == 0 {
		t.Errorf("default GadgetAddr is 0")
	}
}

func ntdllBaseOf(t *testing.T) uintptr {
	t.Helper()
	base := GetModuleBaseAddress("ntdll.dll")
	if base == 0 {
		t.Fatalf("GetModuleBaseAddress(\"ntdll.dll\") returned 0")
	}
	return base
}

func addrInRanges(addr uintptr, ranges [][2]uintptr) bool {
	for _, r := range ranges {
		if addr >= r[0] && addr < r[1] {
			return true
		}
	}
	return false
}

func TestGetRuntimeSyscallTable(t *testing.T) {
	table1, err1 := GetRuntimeSyscallTable()
	if err1 != nil {
		t.Fatalf("GetRuntimeSyscallTable failed: %v", err1)
	}
	if table1 == nil {
		t.Fatalf("GetRuntimeSyscallTable returned nil table")
	}

	table2, err2 := GetRuntimeSyscallTable()
	if err2 != nil {
		t.Fatalf("second GetRuntimeSyscallTable failed: %v", err2)
	}
	if table2 != table1 {
		t.Errorf("GetRuntimeSyscallTable not idempotent: got different tables")
	}
}

func TestNtSyscalls(t *testing.T) {
	table, err := InitializeSyscallTable()
	if err != nil {
		t.Fatalf("InitializeSyscallTable failed: %v", err)
	}

	currentPID := windows.GetCurrentProcessId()

	// Test NtOpenProcess
	hProcess, status, err := NtOpenProcess(table, windows.PROCESS_QUERY_LIMITED_INFORMATION, currentPID)
	if err != nil || status != STATUS_SUCCESS {
		t.Fatalf("NtOpenProcess failed: status=0x%08X, err=%v", status, err)
	}
	defer windows.CloseHandle(hProcess)

	if hProcess == 0 {
		t.Fatalf("NtOpenProcess returned invalid handle: 0")
	}
	t.Logf("NtOpenProcess succeeded with handle 0x%x", hProcess)

	// Test NtOpenProcessToken
	hToken, status, err := NtOpenProcessToken(table, hProcess, windows.TOKEN_QUERY)
	if err != nil || status != STATUS_SUCCESS {
		t.Fatalf("NtOpenProcessToken failed: status=0x%08X, err=%v", status, err)
	}
	defer windows.CloseHandle(hToken)

	if hToken == 0 {
		t.Fatalf("NtOpenProcessToken returned invalid handle: 0")
	}
	t.Logf("NtOpenProcessToken succeeded with handle 0x%x", hToken)
}
