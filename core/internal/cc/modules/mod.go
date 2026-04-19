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
		return
	}

	// filter user supplied option
	exist = hasModuleRunner(modName)
	if !exist {
		logging.Errorf("UpdateOptions: no such module: %s", modName)
		return
	}

	// help us add new options
	addIfNotFound := func(modOpt *def.ModOption) {
		if _, exist := live.ActiveModule.Options[modOpt.Name]; !exist {
			logging.Debugf("UpdateOptions: adding %s", modOpt.Name)
			live.ActiveModule.Options[modOpt.Name] = modOpt
		}
	}

	var modconfig *def.ModuleConfig
	if val, ok := def.Modules.Load(modName); ok {
		modconfig = val.(*def.ModuleConfig)
	}
	if modconfig == nil {
		logging.Errorf("UpdateOptions: module %s config not found", modName)
		return
	}
	if strings.ToLower(modconfig.AgentConfig.Exec) != "built-in" && !modconfig.IsLocal {
		logging.Debugf("UpdateOptions: module %s is not built-in, adding download_addr", modName)
		download_addr := &def.ModOption{
			Name: "download_addr",
			Desc: "Download URL for this module, useful when you want to use an agent as caching server",
			Val:  "",
			Vals: []string{},
		}
		addIfNotFound(download_addr)
	}

	return
}

// ModuleRun run current module
func ModuleRun(ctx *context.C2Context) {
	ensureBuiltInGoModuleRunners()

	if live.ActiveModule == nil {
		logging.Errorf("No active module")
		return
	}
	if live.ActiveAgent != nil {
		target_os := live.ActiveAgent.GOOS
		mod_os := strings.ToLower(live.ActiveModule.Platform)
		if mod_os != "generic" && target_os != mod_os {
			logging.Errorf("ModuleRun: module %s does not support %s", strconv.Quote(live.ActiveModule.Name), target_os)
			return
		}
	}

	// is a target needed?
	if live.ActiveAgent == nil && !live.ActiveModule.IsLocal {
		logging.Errorf("Target not specified")
		return
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
	def.Modules.Range(func(key, value any) bool {
		name := key.(string)
		mod_config := value.(*def.ModuleConfig)
		*search_targets = append(*search_targets, fmt.Sprintf("%s: %s", name, mod_config.Comment))
		return true
	})
	result := fuzzy.Find(keyword, *search_targets)

	// render results
	search_results := make([]*def.ModuleConfig, 0)
	for _, r := range result {
		mod_name := strings.Split(r, ":")[0]
		if val, ok := def.Modules.Load(mod_name); ok {
			mod := val.(*def.ModuleConfig)
			search_results = append(search_results, mod)
		}
	}
	return search_results
}

// SetActiveModule set the active module to use: `use` command
func SetActiveModule(modName string) {
	ensureBuiltInGoModuleRunners()

	if hasModuleRunner(modName) {
		if val, ok := def.Modules.Load(modName); ok {
			live.ActiveModule = val.(*def.ModuleConfig)
		}
		UpdateOptions(modName)
		logging.Infof("Using module %s", strconv.Quote(modName))
		if val, exists := def.Modules.Load(modName); exists {
			mod := val.(*def.ModuleConfig)
			logging.Successf("%s: %s", modName, mod.Comment)

			// OPSEC warnings
			if mod.AgentConfig.Exec != "built-in" && !mod.IsLocal {
				if mod.AgentConfig.Type == "coff" {
					logging.Infof("OPSEC: This is a BOF module, which is recommended for OPSEC (runs in-memory)")
				} else {
					logging.Warningf("OPSEC: This module is NOT built-in and NOT BOF. It may involve fork-and-run or disk activity")
				}
			}
			if mod.AgentConfig.IsInteractive {
				logging.Warningf("OPSEC: Interactive modules like this one involve forking a shell/process on the agent")
			}
			if !mod.Fileless && !mod.IsLocal {
				logging.Warningf("OPSEC: This module is NOT fileless, it WILL touch the agent's disk")
			}
		}
		return
	}
	logging.Errorf("No such module: %s", strconv.Quote(modName))
}
