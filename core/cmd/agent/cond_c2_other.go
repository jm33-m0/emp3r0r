//go:build !linux
// +build !linux

package main

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// conditionalC2FailNotify is a sleep on non-Linux platforms.
func conditionalC2FailNotify() {
	// Wait and retry
	logging.Warningf("Connection failed, sleeping...")
	util.TakeASnap() // sleeps for random interval
}
