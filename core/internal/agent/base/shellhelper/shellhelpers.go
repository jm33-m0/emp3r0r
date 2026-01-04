package shellhelper

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func GetNetworkDetails() (out string) {
	ipa := netutil.IPa()
	ipneigh := netutil.IPNeigh()
	ipr := netutil.IPr()

	out = fmt.Sprintf("[*] ip addr:\n    %s"+
		"\n\n[*] ip route:\n    %s"+
		"\n\n[*] ip neigh:\n    %s\n\n",
		strings.Join(ipa, ", "),
		strings.Join(ipr, ", "),
		strings.Join(ipneigh, ", "))

	return
}

func killProcess(args []string) (out string, err error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no PID specified")
	}

	var (
		pid       int
		proc      *os.Process
		results   []string
		hasErrors bool
	)

	for _, pidStr := range args {
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			results = append(results, fmt.Sprintf("PID '%s': Invalid PID format: %v", pidStr, err))
			hasErrors = true
			continue
		}

		if pid <= 0 {
			results = append(results, fmt.Sprintf("PID %d: Invalid PID (must be positive)", pid))
			hasErrors = true
			continue
		}

		proc, err = os.FindProcess(pid)
		if err != nil {
			results = append(results, fmt.Sprintf("PID %d: Failed to find process: %v", pid, err))
			hasErrors = true
			continue
		}

		// kill process
		err = proc.Kill()
		if err != nil {
			if strings.Contains(err.Error(), "no such process") {
				results = append(results, fmt.Sprintf("PID %d: Process not found (may have already exited)", pid))
			} else if strings.Contains(err.Error(), "permission denied") {
				results = append(results, fmt.Sprintf("PID %d: Permission denied (insufficient privileges)", pid))
			} else if strings.Contains(err.Error(), "operation not permitted") {
				results = append(results, fmt.Sprintf("PID %d: Operation not permitted (may be a system process)", pid))
			} else {
				results = append(results, fmt.Sprintf("PID %d: Failed to kill process: %v", pid, err))
			}
			hasErrors = true
			continue
		}
		results = append(results, fmt.Sprintf("PID %d: Successfully killed", pid))
	}

	out = strings.Join(results, "\n")
	if hasErrors {
		// Return an error to indicate partial or complete failure
		err = fmt.Errorf("one or more kill operations failed")
	}
	return
}

func CmdPS(pid int, user, name, cmdLine string) (out string, err error) {
	empty_proc := &util.ProcEntry{
		Name:    "N/A",
		Cmdline: "N/A",
		Token:   "N/A",
		PID:     0,
		PPID:    0,
	}
	procs := util.ProcessList(pid, user, name, cmdLine)
	if len(procs) == 0 || procs == nil {
		procs = []util.ProcEntry{*empty_proc}
	}

	data, err := cbor.Marshal(procs)
	if err != nil {
		return
	}
	out = string(data)

	return
}
