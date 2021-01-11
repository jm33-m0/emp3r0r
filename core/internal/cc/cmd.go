package cc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/agent"
)

// Commands holds all commands and their help string, command: help
var Commands = map[string]string{
	HELP:           "Print this help, 'help <module>' gives help for a module",
	"target":       "Set target. eg. `target <index>`",
	"set":          "Set an option. eg. `set <option> <val>`",
	"use":          "Use a module. eg. `use <module_name>`",
	"run":          "Run selected module, make sure you have set required options",
	"info":         "What options do we have?",
	"ls_targets":   "List all targets",
	"ls_modules":   "List all modules",
	"ls_port_fwds": "List all port mappings",
	"exit":         "Exit",
}

// CmdHelpers holds a map of helper functions
var CmdHelpers = map[string]func(){
	"ls_targets":   ListTargets,
	"ls_modules":   ListModules,
	"ls_port_fwds": ListPortFwds,
	"info":         CliListOptions,
	"run":          ModuleRun,
}

const HELP = "help" // fuck goconst

// CmdHandler processes user commands
func CmdHandler(cmd string) (err error) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) < 0 {
		return
	}

	switch {
	case cmd == "":
		return
	case cmdSplit[0] == HELP:
		if len(cmdSplit) > 2 {
			CliPrintError("WTF?")
			return
		}
		if len(cmdSplit) == 1 {
			CmdHelp("")
			return
		}
		CmdHelp(cmdSplit[1])

	case cmdSplit[0] == "use":
		if len(cmdSplit) != 2 {
			color.Red("use what? " + strconv.Quote(cmd))
			return
		}

		for mod := range ModuleHelpers {
			if mod == cmdSplit[1] {
				CurrentMod = cmdSplit[1]
				for k := range Options {
					delete(Options, k)
				}
				UpdateOptions(CurrentMod)
				color.HiGreen("Using module '%s'", CurrentMod)
				dynamicPrompt := fmt.Sprintf("%s (%s) "+color.HiCyanString("> "),
					color.HiCyanString("emp3r0r"),
					color.HiBlueString(CurrentMod))
				EmpReadLine.Config.Prompt = dynamicPrompt
				EmpReadLine.SetPrompt(dynamicPrompt)
				return
			}
		}
		color.Red("No such module: '%s'", cmdSplit[1])

	case cmdSplit[0] == "set":
		if len(cmdSplit) < 3 {
			color.Red("set what? " + strconv.Quote(cmd))
			return
		}

		// hand to SetOption helper
		SetOption(cmdSplit[1:])

	case cmdSplit[0] == "target":
		if len(cmdSplit) != 2 {
			color.Red("set target to what? " + strconv.Quote(cmd))
			return
		}
		index, e := strconv.Atoi(cmdSplit[1])
		if e != nil {
			color.Red("Cannot set target: %v", e)
			return e
		}
		CurrentTarget = GetTargetFromIndex(index)

	default:
		helper := CmdHelpers[cmd]
		if helper == nil {
			color.Red("Unknown command: " + strconv.Quote(cmd))
			return
		}
		helper()
	}
	return
}

// CmdHelp prints help in two columns
// print help for modules
func CmdHelp(mod string) {
	help := make(map[string]string)
	switch mod {
	case "":
		CliPrettyPrint("Command", "Description", &Commands)
	case agent.ModLPE_SUGGEST:
		help = map[string]string{
			"lpe_helper": "'unix-privesc-check' or 'linux-exploit-suggester'?",
		}
		CliPrettyPrint("Option", "Help", &help)
	case agent.ModCMD_EXEC:
		help = map[string]string{
			"cmd_to_exec": "Press TAB for some hints",
		}
		CliPrettyPrint("Option", "Help", &help)
	case agent.ModPORT_FWD:
		help = map[string]string{
			"to_port":     "Port (to forward to) on agent/CC side",
			"listen_port": "Listen on CC/agent side",
			"switch":      "Turn port mapping on/off, or use `reverse` mapping",
		}
		CliPrettyPrint("Option", "Help", &help)
	case agent.ModPROXY:
		help = map[string]string{
			"port":   "Port of our local proxy server",
			"status": "Turn proxy on/off",
		}
		CliPrettyPrint("Option", "Help", &help)
	case agent.ModINJECTOR:
		help = map[string]string{
			"pid": "Target process PID, set to 0 to start a new process (sleep)",
		}
		CliPrettyPrint("Option", "Help", &help)
	case agent.ModCLEAN_LOG:
		help = map[string]string{
			"keyword": "Delete all log entries containing this keyword",
		}
		CliPrettyPrint("Option", "Help", &help)
	default:
		for modname, modhelp := range agent.ModuleDocs {
			if mod == modname {
				help = map[string]string{"<N/A>": modhelp}
				CliPrettyPrint("Option", "Help", &help)
				return
			}
		}
		CliPrintError("Help yourself")
	}
}
