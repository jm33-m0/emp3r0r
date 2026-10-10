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
}
