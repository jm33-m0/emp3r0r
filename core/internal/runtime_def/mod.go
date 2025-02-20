package runtime_def

import (
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
)

var (
	// ModuleDir stores modules
	ModuleDirs []string

	// ActiveModule selected module
	ActiveModule = "none"

	// AvailableModuleOptions currently available options for `set`
	AvailableModuleOptions = make(map[string]*emp3r0r_def.ModOption)
)

// SetOption set an option to value, `set` command
func SetOption(opt, val string) {
	// set
	optObj, ok := AvailableModuleOptions[opt]
	if !ok {
		logging.Errorf("option %s not found", strconv.Quote(opt))
		return
	}
	optObj.Val = val
}
