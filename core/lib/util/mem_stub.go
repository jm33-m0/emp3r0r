//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package util

import "fmt"

// Dummy implementation of ReadMemoryRegion for unsupported OSes.
func ReadMemoryRegion(hProcess, address, size uintptr) ([]byte, error) {
	return nil, fmt.Errorf("ReadMemoryRegion not implemented on this OS")
}

// Dummy implementation of DumpProcMem for unsupported OSes.
func DumpProcMem(pid int) (map[int64][]byte, error) {
	return nil, fmt.Errorf("DumpProcMem not implemented on this OS")
}

// Dummy implementation of DumpCurrentProcMem for unsupported OSes.
func DumpCurrentProcMem() (map[int64][]byte, error) {
	return nil, fmt.Errorf("DumpCurrentProcMem not implemented on this OS")
}

// Dummy implementation of MemFDWrite for unsupported OSes.
func MemFDWrite(data []byte) int {
	return -1
}

// Dummy implementation of MiniDumpProcess for unsupported OSes.
func MiniDumpProcess(pid int, file string) error {
	return fmt.Errorf("MiniDumpProcess not implemented on this OS")
}
