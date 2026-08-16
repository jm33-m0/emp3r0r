//go:build !linux
// +build !linux

package main

// conditionalC2FailNotify is a backoff sleep on non-Linux platforms.
func conditionalC2FailNotify() {
	// Back off and retry
	takeC2Backoff()
}
