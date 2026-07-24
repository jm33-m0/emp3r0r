//go:build !linux && !windows
// +build !linux,!windows

package util

// ProcessList a list of current processes with filters on other systems
func ProcessList(pid int, username, command, commandLine string) []ProcEntry {
	return nil
}

// ProcExePath read exe path of a process
func ProcExePath(pid int) string {
	return "dead_process"
}

// ProcCwd read cwd path of a process
func ProcCwd(pid int) string {
	return "dead_process"
}

// ProcCmdline read cmdline data of a process
func ProcCmdline(pid int) string {
	return "dead_process"
}

// IsPIDAlive check if a PID exists
func IsPIDAlive(pid int) bool {
	return false
}

// IsProcAlive check if a process name exists, returns its process(es)
func IsProcAlive(procName string) (bool, []*ProcSimple) {
	return false, nil
}

// PidOf PID of a process name
func PidOf(name string) []int {
	return nil
}

// GetChildren get children processes of a process
func GetChildren(pid int) ([]int, error) {
	return nil, nil
}
