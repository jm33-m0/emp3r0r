package cc

import (
	"strconv"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/lithammer/fuzzysearch/fuzzy"
)

// Option all necessary info of an option
type Option struct {
	Name string   // like `module`, `target`, `cmd_to_exec`
	Val  string   // the value to use
	Vals []string // possible values
}

var (
	// ModuleDir stores modules
	ModuleDirs []string

	// CurrentMod selected module
	CurrentMod = "<blank>"

	// CurrentTarget selected target
	CurrentTarget *emp3r0r_data.AgentSystemInfo

	// Options currently available options for `set`
	Options = make(map[string]*Option)

	// ShellHelpInfo provide utilities like ps, kill, etc
	// deprecated
	ShellHelpInfo = map[string]string{
		HELP:    "Display this help",
		"#ps":   "List processes: `ps`",
		"#kill": "Kill process: `kill <PID>`",
		"#net":  "Show network info",
		"put":   "Put a file from CC to agent: `put <local file> <remote path>`",
		"get":   "Get a file from agent: `get <remote file>`",
	}

	// ModuleHelpers a map of module helpers
	ModuleHelpers = map[string]func(){
		emp3r0r_data.ModCMD_EXEC:     moduleCmd,
		emp3r0r_data.ModSHELL:        moduleShell,
		emp3r0r_data.ModPROXY:        moduleProxy,
		emp3r0r_data.ModPORT_FWD:     modulePortFwd,
		emp3r0r_data.ModLPE_SUGGEST:  moduleLPE,
		emp3r0r_data.ModGET_ROOT:     moduleGetRoot,
		emp3r0r_data.ModCLEAN_LOG:    moduleLogCleaner,
		emp3r0r_data.ModPERSISTENCE:  modulePersistence,
		emp3r0r_data.ModVACCINE:      moduleVaccine,
		emp3r0r_data.ModINJECTOR:     moduleInjector,
		emp3r0r_data.ModREVERSEPROXY: moduleReverseProxy,
		emp3r0r_data.ModGDB:          moduleGDB,
	}
)

// SetOption set an option to value, `set` command
func SetOption(args []string) {
	opt := args[0]
	if len(args) < 2 {
		// clear value
		Options[opt].Val = ""
		return
	}

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
	case modName == emp3r0r_data.ModCMD_EXEC:
		currentOpt = addIfNotFound("cmd_to_exec")
		currentOpt.Vals = []string{
			"id", "whoami", "ifconfig",
			"ip a", "arp -a",
			"ps -ef", "lsmod", "ss -antup",
			"netstat -antup", "uname -a",
		}

	case modName == emp3r0r_data.ModSHELL:
		shellOpt := addIfNotFound("shell")
		shellOpt.Vals = []string{
			"bash", "zsh", "sh", "python", "python3",
			"cmd.exe", "powershell.exe",
		}
		shellOpt.Val = "bash"

		argsOpt := addIfNotFound("args")
		argsOpt.Val = ""
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{
			RuntimeConfig.SSHDPort, "22222",
		}
		portOpt.Val = RuntimeConfig.SSHDPort

	case modName == emp3r0r_data.ModPORT_FWD:
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

	case modName == emp3r0r_data.ModCLEAN_LOG:
		// keyword to clean
		keywordOpt := addIfNotFound("keyword")
		keywordOpt.Vals = []string{"root", "admin"}

	case modName == emp3r0r_data.ModPROXY:
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{"1080", "8080", "10800", "10888"}
		portOpt.Val = "8080"
		statusOpt := addIfNotFound("status")
		statusOpt.Vals = []string{"on", "off", "reverse"}
		statusOpt.Val = "on"

	case modName == emp3r0r_data.ModLPE_SUGGEST:
		currentOpt = addIfNotFound("lpe_helper")
		for name := range LPEHelpers {
			currentOpt.Vals = append(currentOpt.Vals, name)
		}
		currentOpt.Val = "lpe_les"

	case modName == emp3r0r_data.ModINJECTOR:
		pidOpt := addIfNotFound("pid")
		pidOpt.Vals = []string{"0"}
		pidOpt.Val = "0"
		methodOpt := addIfNotFound("method")
		methodOpt.Vals = []string{"gdb_loader", "inject_shellcode", "inject_loader"}
		methodOpt.Val = "inject_shellcode"

	case modName == emp3r0r_data.ModREVERSEPROXY:
		addrOpt := addIfNotFound("addr")
		addrOpt.Vals = []string{"127.0.0.1"}
		addrOpt.Val = "<blank>"

	case modName == emp3r0r_data.ModPERSISTENCE:
		currentOpt = addIfNotFound("method")
		methods := make([]string, len(emp3r0r_data.PersistMethods))
		i := 0
		for k := range emp3r0r_data.PersistMethods {
			methods[i] = k
			i++
		}
		currentOpt.Vals = methods
		currentOpt.Val = "all"

	default:
		// custom modules
		modconfig := ModuleConfigs[modName]
		for opt, val_help := range modconfig.Options {
			argOpt := addIfNotFound(opt)

			argOpt.Val = val_help[0]
		}
	}

	return
}

// ModuleRun run current module
func ModuleRun() {
	if CurrentTarget == nil {
		if CurrentMod == emp3r0r_data.ModCMD_EXEC {
			if !CliYesNo("Run on all targets") {
				CliPrintError("Target not specified")
				return
			}
			ModuleHelpers[emp3r0r_data.ModCMD_EXEC]()
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
func SelectCurrentTarget() (target *emp3r0r_data.AgentSystemInfo) {
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

// search modules, powered by fuzzysearch
func ModuleSearch(cmd string) {
	cmdSplit := strings.Fields(cmd)
	if len(cmdSplit) < 2 {
		CliPrintError("search <module keywords>")
		return
	}
	query := strings.Join(cmdSplit[1:], " ")
	result := fuzzy.Find(query, ModuleNames)
	CliPrintInfo("\n%s\n", strings.Join(result, "\n"))
}
