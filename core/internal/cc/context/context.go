package context

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// C2Context holds the context for a C2 module execution
type C2Context struct {
	// Target is the agent this command targets
	Target *def.Emp3r0rAgent
	// OpSession is the UUID of the operator (for logging/ACLs)
	OpSession string
	// Flags are the runtime flags (replaces live.ActiveModule.Options)
	Flags map[string]string
	// Job is the job associated with this context
	Job *def.Job

	// OnUIReady is an optional callback injected by UI layer
	// Called when a UI action is needed (e.g., opening shell, file manager)
	// The string parameter is typically a connection string or command to execute
	OnUIReady func(connStr string) error
}
