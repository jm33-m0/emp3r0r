package util

import (
	"testing"
)

func TestGetMemSize(t *testing.T) {
	mem := GetMemSize()
	// It might return -1 if ghw fails (e.g. in some containers), which is handled.
	// But it shouldn't crash.
	t.Logf("Memory size: %d MB", mem)
}

func TestGetCPUInfo(t *testing.T) {
	cpu := GetCPUInfo()
	t.Logf("CPU Info: %s", cpu)
	// CPU info might be empty in some environments
}

func TestGetGPUInfo(t *testing.T) {
	gpu := GetGPUInfo()
	t.Logf("GPU Info: %s", gpu)
}
