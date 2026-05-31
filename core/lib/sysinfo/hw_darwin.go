//go:build darwin

package sysinfo

func GetHardwareInfo() string {
	return "Apple Device"
}

func GetCPUInfo() string {
	return "unknown_cpu"
}

func GetGPUInfo() string {
	return "unknown_gpu"
}

func GetMemSize() int {
	return -1
}
