//go:build windows
// +build windows

package util

import (
	"log"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	psapi    = syscall.NewLazyDLL("Psapi.dll")

	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procVirtualQuery       = kernel32.NewProc("VirtualQuery")
	procGetModuleFileName  = kernel32.NewProc("GetModuleFileNameW")
	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")
	procEnumProcessModules = psapi.NewProc("EnumProcessModulesEx")
)

const PROCESS_ALL_ACCESS = 0x1F0FFF

func OpenProcess(pid int) uintptr {
	handle, _, _ := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(1), uintptr(pid))
	return handle
}

func read_mem(hProcess uintptr, address, size uintptr) []byte {
	var data = make([]byte, size)
	var length uint32

	procReadProcessMemory.Call(hProcess, address,
		uintptr(unsafe.Pointer(&data[0])),
		size, uintptr(unsafe.Pointer(&length)))

	return data
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

func read_self_mem(hProcess uintptr) (mem_data [][]byte, bytes_read int, err error) {
	// Start with an initial address of 0
	address := uintptr(0)

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
		// log.Printf("BaseAddress: 0x%x, RegionSize: 0x%x, State: %d, Protect: %d, Type: %d\n",
		// 	mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type)

		// if memory is not committed or is read-only, skip it
		readable := mbi.State == MEM_COMMIT && mbi.Protect&syscall.PAGE_READONLY != 0
		if !readable {
			continue
		}

		// read data from this region
		data_read := read_mem(hProcess, mbi.BaseAddress, mbi.RegionSize)
		bytes_read += len(data_read)
		mem_data = append(mem_data, data_read)
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

func crossPlatformDumpSelfMem() (mem_data [][]byte, err error) {
	dlls, err := GetAllDLLs()
	if err != nil {
		return
	}
	for fileName, dll := range dlls {
		dll_data, err := ReadDLL(dll, fileName)
		if err != nil {
			log.Printf("reading DLL %s: %v", fileName, err)
			continue
		}
		mem_data = append(mem_data, dll_data)
	}
	return mem_data, err
}
