//go:build windows

package sysinfo

func GetHardwareInfo() string {
	return "Windows Device"
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
