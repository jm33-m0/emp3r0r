//go:build linux
// +build linux

package agent

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func ExtractBash() error {
	if !util.IsFileExist(RuntimeConfig.UtilsPath) {
		err := os.MkdirAll(RuntimeConfig.UtilsPath, 0700)
		if err != nil {
			log.Fatalf("[-] Cannot mkdir %s: %v", RuntimeConfig.AgentRoot, err)
		}
	}

	bashData := tun.Base64Decode(emp3r0r_data.BashBinary)
	if bashData == nil {
		log.Printf("bash binary decode failed")
	}
	checksum := tun.SHA256SumRaw(bashData)
	if checksum != emp3r0r_data.BashChecksum {
		return fmt.Errorf("bash checksum error")
	}
	err := ioutil.WriteFile(RuntimeConfig.UtilsPath+"/.bashrc", []byte(emp3r0r_data.BashRC), 0600)
	if err != nil {
		log.Printf("Write bashrc: %v", err)
	}

	return ioutil.WriteFile(RuntimeConfig.UtilsPath+"/bash", bashData, 0755)
}
