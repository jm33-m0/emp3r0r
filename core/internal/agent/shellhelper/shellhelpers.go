package shellhelper

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func CmdNetHelper() (out string) {
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

func CmdKill(args []string) (out string, err error) {
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

	data, err := json.Marshal(procs)
	if err != nil {
		return
	}
	out = string(data)

	return
}
