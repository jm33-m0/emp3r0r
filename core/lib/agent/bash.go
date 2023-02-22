//go:build linux
// +build linux

package agent

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/file"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ExtractBash extract embedded bash binary and configure our bash shell
func ExtractBash() error {
	if !util.IsFileExist(RuntimeConfig.UtilsPath) {
		err := os.MkdirAll(RuntimeConfig.UtilsPath, 0700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", RuntimeConfig.AgentRoot, err)
		}
	}

	// bashData := tun.Base64Decode(file.BashBinary)
	// if bashData == nil {
	// 	log.Printf("bash binary decode failed")
	// }
	// checksum := tun.SHA256SumRaw(bashData)
	// if checksum != file.BashChecksum {
	// 	return fmt.Errorf("bash checksum error")
	// }
	err := ioutil.WriteFile(RuntimeConfig.UtilsPath+"/.bashrc", []byte(file.BashRC), 0600)
	if err != nil {
		log.Printf("Write bashrc: %v", err)
	}

	// return ioutil.WriteFile(RuntimeConfig.UtilsPath+"/bash", bashData, 0755)
	return err
}
