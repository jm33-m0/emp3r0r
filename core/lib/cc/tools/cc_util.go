package tools

import (
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// IsCCRunning check if CC is already running
func IsCCRunning() bool {
	// it is running if we can connect to it
	return tun.IsPortOpen("127.0.0.1", def.RuntimeConfig.CCPort)
}

// UnlockDownloads if there are incomplete file downloads that are "locked", unlock them
// unless CC is actually running/downloading
func UnlockDownloads() error {
	// unlock downloads
	files, err := os.ReadDir(def.FileGetDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".lock") {
			err = os.Remove(def.FileGetDir + f.Name())
			logging.Debugf("Unlocking download: %s", f.Name())
			if err != nil {
				return fmt.Errorf("remove %s: %v", f.Name(), err)
			}
		}
	}

	return nil
}
