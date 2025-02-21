//go:build linux
// +build linux

package external_file

import (
	"fmt"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ExtractBashRC extract embedded bashrc and configure our bash shell
func ExtractBashRC(bash, bashrc string) error {
	bashrcData, err := ExtractFileFromString(BashRC)
	if err != nil {
		return fmt.Errorf("extract bashrc: %v", err)
	}
	err = os.WriteFile(bashrc, bashrcData, 0o600)
	if err != nil {
		log.Printf("Write bashrc: %v", err)
	}

	if !util.IsFileExist(bash) {
		return fmt.Errorf("custom bash binary (%s) not found, maybe you need to run `vaccine`",
			bash)

	}

	return err
}
