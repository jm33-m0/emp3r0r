package shellhelper

import (
	"fmt"
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

	return out
}

func CmdPS(pid int, user, name, cmdLine string) (out []byte, err error) {
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

	return cbor.Marshal(procs)
}
