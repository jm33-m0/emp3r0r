//go:build linux
// +build linux

package main

import (
	"syscall"
)

// conditionalC2FailNotify tells the parent (stager/loader) to recycle us.
func conditionalC2FailNotify() {
	// Suspend self (Stager will encrypt and sleep us)
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
}
