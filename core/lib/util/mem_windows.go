//go:build windows
// +build windows

package util

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	psapi    = syscall.NewLazyDLL("Psapi.dll")
	dbghelp  = syscall.NewLazyDLL("Dbghelp.dll")

	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procVirtualQuery       = kernel32.NewProc("VirtualQuery")
	procGetModuleFileName  = kernel32.NewProc("GetModuleFileNameW")
	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")
	procEnumProcessModules = psapi.NewProc("EnumProcessModulesEx")
	procMiniDumpWriteDump  = dbghelp.NewProc("MiniDumpWriteDump")
)

const (
	PROCESS_ALL_ACCESS     = 0x1F0FFF
	MiniDumpWithFullMemory = 0x00000002
)

// OpenProcess opens a Windows process, returns a handle
func OpenProcess(pid int) uintptr {
	handle, _, _ := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(1), uintptr(pid))
	return handle
}

// ReadMemoryRegion reads memory region from a process
func ReadMemoryRegion(hProcess uintptr, address, size uintptr) ([]byte, error) {
	data := make([]byte, size)
	var length uint32

	procReadProcessMemory.Call(hProcess, address,
		uintptr(unsafe.Pointer(&data[0])),
		size, uintptr(unsafe.Pointer(&length)))

	return data, nil
}

const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_FREE    = 0x10000
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// DumpProcessMem dumps all memory regions of a process
func DumpProcessMem(hProcess uintptr) (mem_data map[int64][]byte, bytes_read int, err error) {
	// Start with an initial address of 0
	address := uintptr(0)

	mem_data = make(map[int64][]byte)

	// Loop through the memory regions and print information
	for {
		var mbi MEMORY_BASIC_INFORMATION
		ret, _, _ := procVirtualQuery.Call(address, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))

		// Check for the end of the memory regions
		if ret == 0 {
			break
		}

		// Move to the next memory region
		address += mbi.RegionSize

		// Print information about the memory region
		logging.Debugf("BaseAddress: 0x%x, RegionSize: 0x%x, State: %d, Protect: %d, Type: %d\n",
			mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type)

		// if memory is not committed or is read-only, skip it
		readable := mbi.State == MEM_COMMIT && mbi.Protect&syscall.PAGE_READONLY != 0
		if !readable {
			continue
		}

		// read data from this region
		data_read, _ := ReadMemoryRegion(hProcess, mbi.BaseAddress, mbi.RegionSize)
		bytes_read += len(data_read)
		mem_data[int64(mbi.BaseAddress)] = data_read
	}

	return
}

func write_mem(hProcess uintptr, lpBaseAddress, lpBuffer, nSize uintptr) (int, bool) {
	var nBytesWritten int
	ret, _, _ := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		lpBuffer,
		nSize,
		uintptr(unsafe.Pointer(&nBytesWritten)),
	)

	return nBytesWritten, ret != 0
}

func getBaseAddress(handle uintptr) uintptr {
	modules := [1024]uint64{}
	var needed uintptr
	procEnumProcessModules.Call(
		handle,
		uintptr(unsafe.Pointer(&modules)),
		uintptr(1024),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(0x03),
	)
	for i := uintptr(0); i < needed/unsafe.Sizeof(modules[0]); i++ {
		if i == 0 {
			return uintptr(modules[i])
		}
	}
	return 0
}

// DumpProcMem dumps all memory regions of a process given its PID
func DumpProcMem(pid int) (mem_data map[int64][]byte, err error) {
	hProcess := OpenProcess(pid)
	if hProcess == 0 {
		err = syscall.GetLastError()
		return
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	mem_data, _, err = DumpProcessMem(hProcess)
	return
}

// DumpCurrentProcMem dumps all memory regions of the current process
func DumpCurrentProcMem() (mem_data map[int64][]byte, err error) {
	mem_data = make(map[int64][]byte)
	dlls, err := GetAllDLLs()
	if err != nil {
		return
	}
	for fileName, dll := range dlls {
		dll_data, err := ReadDLL(dll, fileName)
		if err != nil {
			logging.Debugf("reading DLL %s: %v", fileName, err)
			continue
		}
		mem_data[int64(dll.BaseOfDll)] = dll_data
	}

	// dump all memory regions
	self_mem_data, err := DumpProcMem(os.Getpid())
	if err != nil {
		logging.Debugf("reading self memory: %v", err)
	}
	for base, data := range self_mem_data {
		mem_data[base] = data
	}

	return mem_data, err
}

// MiniDumpProcess creates a minidump of the given process
func MiniDumpProcess(pid int, dumpFile string) error {
	var err error
	hProcess := OpenProcess(pid)
	if hProcess == 0 {
		err = syscall.GetLastError()
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))
	file, err := os.Create(dumpFile)
	if err != nil {
		return err
	}
	defer file.Close()

	hFile := syscall.Handle(file.Fd())
	ret, _, _ := procMiniDumpWriteDump.Call(
		uintptr(hProcess),
		uintptr(pid),
		uintptr(hFile),
		uintptr(MiniDumpWithFullMemory),
		0,
		0,
		0,
	)

	if ret == 0 {
		err = syscall.GetLastError()
		return err
	}

	return nil
}
