package def

import emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"

var (
	// ModuleDir stores modules
	ModuleDirs []string

	// ActiveModule selected module
	ActiveModule = "none"

	// AvailableModuleOptions currently available options for `set`
	AvailableModuleOptions = make(map[string]*emp3r0r_def.ModOption)
)
