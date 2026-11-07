package live

import "sync/atomic"

// lastJobID records the most recently dispatched job in this process. The
// operator console uses it so a follow-up command (for example `ask --last`)
// can refer to the output the operator just saw without copying a UUID.
var lastJobID atomic.Value // string

// SetLastJobID publishes the job that was just dispatched. Empty IDs are
// ignored so a call site without a job cannot clear a useful reference.
func SetLastJobID(id string) {
	if id != "" {
		lastJobID.Store(id)
	}
}

// LastJobID returns the most recently dispatched job ID, or "" when no job
// has been dispatched in this process.
func LastJobID() string {
	id, _ := lastJobID.Load().(string)
	return id
}
