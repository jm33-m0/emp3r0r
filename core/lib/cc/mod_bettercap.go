package cc

import (
	"strconv"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func moduleBettercap() {
	if !CurrentTarget.HasRoot {
		CliPrintError("Sorry, bettercap must be run as root, try `use get_root`?")
		return
	}

	args := Options["args"].Val
	port := strconv.Itoa(util.RandInt(1024, 65535))
	err := SSHClient(emp3r0r_data.UtilsPath+"/bettercap", args, port, false)
	if err != nil {
		CliPrintError("moduleBettercap: %v", err)
	}
}
