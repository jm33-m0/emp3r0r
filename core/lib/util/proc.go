package util

import (
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ProcEntry a process entry of a process list
type ProcEntry struct {
	Name      string `json:"name" cbor:"1,keyasint"`      // process name
	Cmdline   string `json:"cmdline" cbor:"2,keyasint"`   // process cmdline
	Token     string `json:"token" cbor:"3,keyasint"`     // process token/username
	PID       int    `json:"pid" cbor:"4,keyasint"`       // process ID
	PPID      int    `json:"ppid" cbor:"5,keyasint"`      // parent process ID
	UID       string `json:"uid" cbor:"6,keyasint"`       // user ID (UID on Linux, SID on Windows)
	Namespace string `json:"namespace" cbor:"7,keyasint"` // Linux namespace info
}

// ProcSimple represents basic process info for IsProcAlive
type ProcSimple struct {
	Pid int32
}

// sleep for a random interval between 5s to 60s
var TakeASnap = func() {
	interval := time.Duration(RandInt(5000, 60000)) * time.Millisecond
	for {
		start := time.Now()
		time.Sleep(interval)
		elapsed := time.Since(start)
		if elapsed >= interval {
			break
		}
		// If we are here, it means the sleep was interrupted or skipped.
		// We subtract the elapsed time and try to sleep the remainder.
		logging.Debugf("TakeASnap: sleep was interrupted/skipped (%v < %v), sleeping remainder", elapsed, interval)
		interval -= elapsed
	}
}

// sleep for a random interval between 100ms to 500ms
func TakeABlink() {
	interval := time.Duration(RandInt(100, 500))
	time.Sleep(interval * time.Millisecond)
}
