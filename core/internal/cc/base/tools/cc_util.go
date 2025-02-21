package tools

import (
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

// IsCCRunning check if CC is already running
func IsCCRunning() bool {
	// it is running if we can connect to it
	return netutil.IsPortOpen("127.0.0.1", live.RuntimeConfig.CCPort)
}

// UnlockDownloads if there are incomplete file downloads that are "locked", unlock them
// unless CC is actually running/downloading
func UnlockDownloads() error {
	// unlock downloads
	files, err := os.ReadDir(live.FileGetDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".lock") {
			err = os.Remove(live.FileGetDir + f.Name())
			logging.Debugf("Unlocking download: %s", f.Name())
			if err != nil {
				return fmt.Errorf("remove %s: %v", f.Name(), err)
			}
		}
	}

	return nil
}
