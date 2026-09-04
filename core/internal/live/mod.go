package live

import (
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

var (
	// ModuleDir stores modules
	ModuleDirs []string

	// ActiveModule is the module currently being run. It is set right before
	// each module invocation and its options are never mutated by a run:
	// parameter values live for a single execution only.
	ActiveModule *def.ModuleConfig
)
