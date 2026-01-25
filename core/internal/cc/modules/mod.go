package modules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/spf13/cobra"
)

var (
	// ShellHelpInfo provide utilities like ps, kill, etc
	// deprecated
	ShellHelpInfo = map[string]string{
		"#ps":   "List processes: `ps`",
		"#kill": "Kill process: `kill <PID>`",
		"#net":  "Show network info",
		"put":   "Put a file from CC to agent: `put <local file> <remote path>`\nPath starting with `mem://` enforces memory storage. Otherwise smart selection is used.\nUse --force to write to disk if memory fails.",
		"get":   "Get a file from agent: `get <remote file>`",
	}

	// ModuleRunners a map of module helpers
	ModuleRunners = map[string]func(){
		def.ModCMD_EXEC:    moduleCmd,
		def.ModSHELL:       moduleShell,
		def.ModPROXY:       moduleProxy,
		def.ModPORT_FWD:    modulePortFwd,
		def.ModLPE_SUGGEST: moduleLPE,
		def.ModCLEAN_LOG:   moduleLogCleaner,

		def.ModBring2CC:     moduleBring2CC,
		def.ModListener:     modListener,
		def.ModSSHHarvester: module_ssh_harvester,
		def.ModDownloader:   moduleDownloader,
		def.ModFileServer:   moduleFileServer,
		def.ModMemDump:      moduleMemDump,

		def.ModSCREENSHOT: moduleScreenshot,
	}
)

// UpdateOptions reads options from modules config, and set default values
func UpdateOptions(modName string) (exist bool) {
	if live.ActiveModule == nil {
		logging.Errorf("No active module")
		return
	}

	// filter user supplied option
	for mod := range ModuleRunners {
		if mod == modName {
			exist = true
			break
		}
	}
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

	modconfig := def.Modules[modName]
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
func ModuleRun() {
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
	mod := ModuleRunners[live.ActiveModule.Name]
	if mod != nil {
		go mod()
	} else {
		logging.Errorf("Module %s has no runner", strconv.Quote(live.ActiveModule.Name))
	}
}

func CmdModuleSearch(cmd *cobra.Command, args []string) {
	ModuleSearch(args[0])
}

// search modules, powered by fuzzysearch
func ModuleSearch(keyword string) []*def.ModuleConfig {
	search_targets := new([]string)
	for name, mod_config := range def.Modules {
		*search_targets = append(*search_targets, fmt.Sprintf("%s: %s", name, mod_config.Comment))
	}
	result := fuzzy.Find(keyword, *search_targets)

	// render results
	search_results := make([]*def.ModuleConfig, 0)
	for _, r := range result {
		mod_name := strings.Split(r, ":")[0]
		mod, ok := def.Modules[mod_name]
		if ok {
			search_results = append(search_results, mod)
		}
	}
	return search_results
}

// SetActiveModule set the active module to use: `use` command
func SetActiveModule(modName string) {
	for mod := range ModuleRunners {
		if mod == modName {
			live.ActiveModule = def.Modules[modName]
			UpdateOptions(modName)
			logging.Infof("Using module %s", strconv.Quote(modName))
			mod, exists := def.Modules[modName]
			if exists {
				logging.Successf("%s: %s", modName, mod.Comment)
			}
			return
		}
	}
	logging.Errorf("No such module: %s", strconv.Quote(modName))
}
