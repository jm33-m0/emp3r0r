package util

import "fmt"

// Dummy implementation of ReadMemoryRegion for Darwin.
func ReadMemoryRegion(hProcess uintptr, address, size uintptr) ([]byte, error) {
	return nil, fmt.Errorf("ReadMemoryRegion not implemented on Darwin")
}

// Dummy implementation of DumpProcMem for Darwin.
func DumpProcMem(pid int) (map[int64][]byte, error) {
	return nil, fmt.Errorf("DumpProcMem not implemented on Darwin")
}

// Dummy implementation of DumpCurrentProcMem for Darwin.
func DumpCurrentProcMem() (map[int64][]byte, error) {
	return nil, fmt.Errorf("DumpCurrentProcMem not implemented on Darwin")
}

// Dummy implementation of MemFDWrite for Darwin.
func MemFDWrite(data []byte) int {
	return -1
}

// Dummy implementation of MiniDumpProcess for Darwin.
func MiniDumpProcess(pid int, file string) error {
	return fmt.Errorf("MiniDumpProcess not implemented on Darwin")
}
