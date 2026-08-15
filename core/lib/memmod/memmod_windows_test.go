//go:build windows

package memmod

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

// skipUnderRace skips memmod tests when the race detector is enabled (the CI
// workflow sets EMP3R0R_RACE_ON=1 for the race step). memmod maps arbitrary
// non-Go memory and performs unsafe pointer arithmetic, which trip Go's
// checkptr validation under -race.
func skipUnderRace(t *testing.T) {
	t.Helper()
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector is enabled")
	}
}

// ensureSyscallTable initializes the global syscall table used by the Nt*
// wrappers if it has not already been set up.
func ensureSyscallTable(t *testing.T) *ntsyscall.SyscallTable {
	t.Helper()
	skipUnderRace(t)
	if ntsyscall.RuntimeSyscallTable == nil {
		table, err := ntsyscall.InitializeSyscallTable()
		if err != nil {
			t.Fatalf("InitializeSyscallTable failed: %v", err)
		}
		ntsyscall.RuntimeSyscallTable = table
	}
	return ntsyscall.RuntimeSyscallTable
}

// readSystemDLL returns the bytes of a DLL from the system directory that
// matches the architecture of the current process.
func readSystemDLL(t *testing.T, name string) []byte {
	t.Helper()
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = os.Getenv("WINDIR")
	}
	if systemRoot == "" {
		t.Fatal("SystemRoot/WINDIR environment variable not set")
	}
	path := filepath.Join(systemRoot, "System32", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}

func TestLoadLibraryNtdll(t *testing.T) {
	ensureSyscallTable(t)
	data := readSystemDLL(t, "ntdll.dll")

	module, err := LoadLibrary(data)
	if err != nil {
		t.Fatalf("LoadLibrary(ntdll.dll) failed: %v", err)
	}
	defer module.Free()

	if module.BaseAddr() == 0 {
		t.Fatal("module base address is 0")
	}
	t.Logf("ntdll.dll loaded at 0x%x", module.BaseAddr())
}

func TestProcAddressByNameAndCall(t *testing.T) {
	ensureSyscallTable(t)
	data := readSystemDLL(t, "ntdll.dll")

	module, err := LoadLibrary(data)
	if err != nil {
		t.Fatalf("LoadLibrary(ntdll.dll) failed: %v", err)
	}
	defer module.Free()

	proc, err := module.ProcAddressByName("RtlNtStatusToDosError")
	if err != nil {
		t.Fatalf("ProcAddressByName(RtlNtStatusToDosError) failed: %v", err)
	}
	if proc == 0 {
		t.Fatal("ProcAddressByName returned 0")
	}

	// STATUS_SUCCESS must map to ERROR_SUCCESS (0).
	r0, _, _ := syscall.SyscallN(proc, uintptr(windows.STATUS_SUCCESS))
	if got := uint32(r0); got != uint32(windows.ERROR_SUCCESS) {
		t.Fatalf("RtlNtStatusToDosError(STATUS_SUCCESS) = %d, want %d", got, windows.ERROR_SUCCESS)
	}

	// STATUS_ACCESS_DENIED must map to ERROR_ACCESS_DENIED (5).
	r0, _, _ = syscall.SyscallN(proc, uintptr(windows.STATUS_ACCESS_DENIED))
	if got := uint32(r0); got != uint32(windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("RtlNtStatusToDosError(STATUS_ACCESS_DENIED) = %d, want %d", got, windows.ERROR_ACCESS_DENIED)
	}

	t.Log("RtlNtStatusToDosError called successfully via memmod-loaded ntdll.dll")
}

func TestProcAddressByOrdinal(t *testing.T) {
	ensureSyscallTable(t)
	data := readSystemDLL(t, "ntdll.dll")

	module, err := LoadLibrary(data)
	if err != nil {
		t.Fatalf("LoadLibrary(ntdll.dll) failed: %v", err)
	}
	defer module.Free()

	byName, err := module.ProcAddressByName("RtlNtStatusToDosError")
	if err != nil {
		t.Fatalf("ProcAddressByName failed: %v", err)
	}

	ordinal, ok := module.nameExports["RtlNtStatusToDosError"]
	if !ok {
		t.Fatal("nameExports does not contain RtlNtStatusToDosError")
	}

	// nameExports stores the index into AddressOfFunctions. ProcAddressByOrdinal
	// expects the full export ordinal, which is Base + index.
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	fullOrdinal := ordinal + uint16(exports.Base)

	byOrdinal, err := module.ProcAddressByOrdinal(fullOrdinal)
	if err != nil {
		t.Fatalf("ProcAddressByOrdinal(%d) failed: %v", fullOrdinal, err)
	}

	if byOrdinal != byName {
		t.Fatalf("ProcAddressByOrdinal = 0x%x, ProcAddressByName = 0x%x", byOrdinal, byName)
	}
}
