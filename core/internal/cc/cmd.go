package cc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// Commands holds all commands and their help string, command: help
var Commands = map[string]string{
	"target":       "Set target. eg. `target <index>`",
	"set":          "Set an option. eg. `set <option> <val>`",
	"use":          "Use a module. eg. `use <module_name>`",
	"run":          "Run selected module, make sure you have set required options",
	"info":         "What options do we have?",
	"ls_targets":   "List all targets",
	"ls_modules":   "List all modules",
	"ls_port_fwds": "List all port mappings",
	"help":         "Print this help",
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

// CmdHandler processes user commands
func CmdHandler(cmd string) (err error) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) < 0 {
		return
	}

	switch {
	case cmd == "":
		return
	case cmdSplit[0] == "help":
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
				EmpReadLine.SetPrompt(
					fmt.Sprintf("%s (%s) "+color.HiCyanString("> "),
						color.HiCyanString("emp3r0r"),
						color.HiBlueString(CurrentMod)))
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
	case "lpe_suggest":
		help = map[string]string{
			"lpe_helper": "'unix-privesc-check' or 'linux-exploit-suggester'?",
		}
		CliPrettyPrint("Option", "Help", &help)
	case "cmd":
		help = map[string]string{
			"cmd_to_exec": "Press TAB for some hints",
		}
		CliPrettyPrint("Option", "Help", &help)
	case "port_fwd":
		help = map[string]string{
			"to_port":     "Port (to forward to) on agent side",
			"listen_port": "Listen on CC side",
			"switch":      "Turn port mapping On/Off",
		}
		CliPrettyPrint("Option", "Help", &help)
	case "proxy":
		help = map[string]string{
			"port":   "Port of our local proxy server",
			"status": "Turn proxy On/Off",
		}
		CliPrettyPrint("Option", "Help", &help)
	case "clean_log":
		help = map[string]string{
			"keyword": "Delete all log entries containing this keyword",
		}
		CliPrettyPrint("Option", "Help", &help)
	default:
		CliPrintError("Help yourself")
	}
}
