package modules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var (
	// ShellHelpInfo provide utilities like ps, kill, etc
	// deprecated
	ShellHelpInfo = map[string]string{
		"#ps":   "List processes: `ps`",
		"#kill": "Kill process: `kill <PID>`",
		"#net":  "Show network info",
		"put":   "Put a file from CC to agent: `put <local file> <remote path>`",
		"get":   "Get a file from agent: `get <remote file>`",
	}

	// ModuleHelpers a map of module helpers
	ModuleHelpers = map[string]func(){
		def.ModCMD_EXEC:     moduleCmd,
		def.ModSHELL:        moduleShell,
		def.ModPROXY:        moduleProxy,
		def.ModPORT_FWD:     modulePortFwd,
		def.ModLPE_SUGGEST:  moduleLPE,
		def.ModCLEAN_LOG:    moduleLogCleaner,
		def.ModPERSISTENCE:  modulePersistence,
		def.ModVACCINE:      moduleVaccine,
		def.ModINJECTOR:     moduleInjector,
		def.ModBring2CC:     moduleBring2CC,
		def.ModListener:     modListener,
		def.ModSSHHarvester: module_ssh_harvester,
		def.ModDownloader:   moduleDownloader,
		def.ModFileServer:   moduleFileServer,
		def.ModMemDump:      moduleMemDump,
	}
)

// UpdateOptions reads options from modules config, and set default values
func UpdateOptions(modName string) (exist bool) {
	// filter user supplied option
	for mod := range ModuleHelpers {
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
		if _, exist := live.AvailableModuleOptions[modOpt.Name]; !exist {
			logging.Debugf("UpdateOptions: adding %s", modOpt.Name)
			live.AvailableModuleOptions[modOpt.Name] = modOpt
		}
	}

	modconfig := def.Modules[modName]
	for optName, option := range modconfig.Options {
		argOpt := modconfig.Options[optName]
		if len(option.Vals) == 0 && option.Val != "" {
			argOpt.Vals = []string{option.Val}
		}
		addIfNotFound(argOpt)
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
func ModuleRun(_ *cobra.Command, _ []string) {
	modObj := def.Modules[live.ActiveModule]
	if modObj == nil {
		logging.Errorf("ModuleRun: module %s not found", strconv.Quote(live.ActiveModule))
		return
	}
	if live.ActiveAgent != nil {
		target_os := live.ActiveAgent.GOOS
		mod_os := strings.ToLower(modObj.Platform)
		if mod_os != "generic" && target_os != mod_os {
			logging.Errorf("ModuleRun: module %s does not support %s", strconv.Quote(live.ActiveModule), target_os)
			return
		}
	}

	// is a target needed?
	if live.ActiveAgent == nil && !modObj.IsLocal {
		logging.Errorf("Target not specified")
		return
	}

	// check if target exists
	if live.AgentControlMap[live.ActiveAgent] == nil && live.ActiveAgent != nil {
		logging.Errorf("Target (%s) does not exist", live.ActiveAgent.Tag)
		return
	}

	// run module
	mod := ModuleHelpers[live.ActiveModule]
	if mod != nil {
		go mod()
	} else {
		logging.Errorf("Module %s not found", strconv.Quote(live.ActiveModule))
	}
}

// search modules, powered by fuzzysearch
func ModuleSearch(cmd *cobra.Command, args []string) {
	keyword := args[0]
	search_targets := new([]string)
	for name, mod_config := range def.Modules {
		*search_targets = append(*search_targets, fmt.Sprintf("%s: %s", name, mod_config.Comment))
	}
	result := fuzzy.Find(keyword, *search_targets)

	// render results
	search_results := make(map[string]string)
	for _, r := range result {
		r_split := strings.Split(r, ": ")
		if len(r_split) == 2 {
			search_results[r_split[0]] = r_split[1]
		}
	}
	cli.CliPrettyPrint("Module", "Comment", &search_results)
}

// CmdListModOptionsTable list currently available options for `set`, in a table
func CmdListModOptionsTable(_ *cobra.Command, _ []string) {
	if live.ActiveModule == "none" {
		logging.Warningf("No module selected")
		return
	}
	live.AgentControlMapMutex.RLock()
	defer live.AgentControlMapMutex.RUnlock()
	opts := make(map[string]string)

	opts["module"] = live.ActiveModule
	if live.ActiveAgent != nil {
		_, exist := live.AgentControlMap[live.ActiveAgent]
		if exist {
			shortName := strings.Split(live.ActiveAgent.Tag, "-agent")[0]
			opts["target"] = shortName
		} else {
			opts["target"] = "<blank>"
		}
	} else {
		opts["target"] = "<blank>"
	}

	for opt_name, opt := range live.AvailableModuleOptions {
		if opt != nil {
			opts[opt_name] = opt.Name
		}
	}

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Option", "Help", "Value"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetColWidth(50)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})
	table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor})

	// fill table
	module_obj := def.Modules[live.ActiveModule]
	if module_obj == nil {
		logging.Errorf("Module %s not found", live.ActiveModule)
		return
	}
	for opt_name, opt_obj := range live.AvailableModuleOptions {
		help := "N/A"
		if opt_obj == nil {
			continue
		}
		help = opt_obj.Desc
		switch opt_name {
		case "module":
			help = "Selected module"
		case "target":
			help = "Selected target"
		}
		val := ""
		currentOpt, ok := live.AvailableModuleOptions[opt_name]
		if ok {
			val = currentOpt.Val
		}

		tdata = append(tdata,
			[]string{
				util.SplitLongLine(opt_name, 50),
				util.SplitLongLine(help, 50),
				util.SplitLongLine(val, 50),
			})
	}
	table.AppendBulk(tdata)
	table.Render()
	out := tableString.String()
	cli.AdaptiveTable(out)
	logging.Printf("\n%s", out)
}

// CmdSetOptVal set an option to value: `set` command
func CmdSetOptVal(cmd *cobra.Command, args []string) {
	opt := args[0]
	val := args[1]
	// hand to SetOption helper
	live.SetOption(opt, val)
	CmdListModOptionsTable(cmd, args)
}

// SetActiveModule set the active module to use: `use` command
func CmdSetActiveModule(cmd *cobra.Command, args []string) {
	modName := args[0]
	for mod := range ModuleHelpers {
		if mod == modName {
			live.ActiveModule = modName
			for k := range live.AvailableModuleOptions {
				delete(live.AvailableModuleOptions, k)
			}
			UpdateOptions(live.ActiveModule)
			logging.Infof("Using module %s", strconv.Quote(live.ActiveModule))
			ModuleDetails(live.ActiveModule)
			mod, exists := def.Modules[live.ActiveModule]
			if exists {
				logging.Printf("%s", mod.Comment)
			}
			CmdListModOptionsTable(cmd, args)

			return
		}
	}
	logging.Errorf("No such module: %s", strconv.Quote(modName))
}
