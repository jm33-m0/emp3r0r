//go:build linux

package main

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// conditionalC2FailNotify tells the parent (stager/loader) to recycle us.
func conditionalC2FailNotify() {
	if common.RuntimeConfig.IsRunByStager {
		// A supervising launcher is waiting on this child. Exit cleanly: the
		// kernel reclaims every byte of agent memory on exit, and the launcher
		// reaps us and restarts a fresh process with the identity key it
		// cached. No signal is needed to trigger the recycle.
		logging.Warningf("Agent lifecycle ended, exiting for launcher to recycle us")
		os.Exit(0)
	}

	// Otherwise, back off and retry
	takeC2Backoff()
}
