package modules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/lithammer/fuzzysearch/fuzzy"
)

// ModuleRunners a map of module helpers
var ModuleRunners = make(map[string]func(ctx *context.C2Context))

// UpdateOptions reads options from modules config, and set default values
func UpdateOptions(modName string) (exist bool) {
	ensureBuiltInGoModuleRunners()

	if live.ActiveModule == nil {
		logging.Errorf("No active module")
		return exist
	}

	// filter user supplied option
	exist = hasModuleRunner(modName)
	if !exist {
		logging.Errorf("UpdateOptions: no such module: %s", modName)
		return exist
	}

	modconfig, ok := def.GetModule(modName)
	if !ok || modconfig == nil {
		logging.Errorf("UpdateOptions: module %s config not found", modName)
		return exist
	}
	return exist
}

// ModuleRun run current module
func ModuleRun(ctx *context.C2Context) {
	ensureBuiltInGoModuleRunners()

	if live.ActiveModule == nil {
		logging.Errorf("No active module")
		return
	}
	// Snapshot the selected target once: it can be replaced concurrently by
	// the agent-list refresher.
	active := live.GetActiveAgent()

	// A local C2 module runs entirely on the operator host and never reaches an
	// agent, so neither the selected target's OS nor the presence of a target
	// is relevant. Its Platform field (when set) only describes the OS its
	// generated payload targets, not where the module runs.
	if !live.ActiveModule.IsLocal {
		if active != nil {
			target_os := active.GOOS
			mod_os := strings.ToLower(live.ActiveModule.Platform)
			if mod_os != "generic" && target_os != mod_os {
				logging.Errorf("ModuleRun: module %s does not support %s", strconv.Quote(live.ActiveModule.Name), target_os)
				return
			}
		}

		// an agent module needs a target to run on
		if active == nil {
			logging.Errorf("Target not specified")
			return
		}
	}

	// run module
	mod := getModuleRunner(live.ActiveModule.Name)
	if mod != nil {
		go mod(ctx)
	} else {
		logging.Errorf("Module %s has no runner", strconv.Quote(live.ActiveModule.Name))
	}
}

// ModuleSearch searches modules, powered by fuzzysearch
func ModuleSearch(keyword string) []*def.ModuleConfig {
	search_targets := new([]string)
	def.ForEachModule(func(name string, mod_config *def.ModuleConfig) {
		*search_targets = append(*search_targets, fmt.Sprintf("%s: %s", name, mod_config.Comment))
	})
	result := fuzzy.Find(keyword, *search_targets)

	// render results
	search_results := make([]*def.ModuleConfig, 0)
	for _, r := range result {
		mod_name := strings.Split(r, ":")[0]
		if mod, ok := def.GetModule(mod_name); ok {
			search_results = append(search_results, mod)
		}
	}
	return search_results
}

// SetActiveModule marks modName as the module being run. It is invoked right
// before a module command executes (there is no interactive `use` command):
// parameter values are read from the command line for that run only and never
// persisted into the shared module config.
func SetActiveModule(modName string) {
	ensureBuiltInGoModuleRunners()

	if hasModuleRunner(modName) {
		mod, ok := def.GetModule(modName)
		if !ok {
			logging.Errorf("No such module: %s", strconv.Quote(modName))
			return
		}
		live.ActiveModule = mod
		UpdateOptions(modName)
		logging.Infof("Using module %s", strconv.Quote(modName))
		logging.Successf("%s: %s", modName, mod.Comment)
		return
	}
	logging.Errorf("No such module: %s", strconv.Quote(modName))
}
