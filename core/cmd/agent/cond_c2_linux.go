//go:build linux
// +build linux

package main

import (
	"os"
)

// conditionalC2FailNotify tells the parent (stager/loader) to recycle us.
func conditionalC2FailNotify() {
	// Exit cleanly (Stager will encrypt and sleep us, then restart)
	os.Exit(0)
}
