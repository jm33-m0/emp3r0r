package handler

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestSysinfoCmdRun(t *testing.T) {
	// Initialize RuntimeConfig if needed
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.AgentTag = "test-agent"

	// Mock C2 connection
	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	rootCmd := CoreCommands()

	// Test 1: sysinfo --full
	rootCmd.SetArgs([]string{"sysinfo", "--full"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute sysinfo --full: %v", err)
	}

	var msg def.MsgTunData
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}

	// Parse the Sysinfo response (it's also CBOR)
	var info def.Emp3r0rAgent
	if err := cbor.Unmarshal(msg.Response, &info); err != nil {
		t.Fatalf("Failed to unmarshal sysinfo response: %v", err)
	}

	if info.Hostname == "" || info.CPU == "" {
		t.Errorf("Expected full sysinfo (Hostname/CPU), got: %+v", info)
	}
	mockConn.Reset()

	// Re-init root command to clear flags
	rootCmd = CoreCommands()

	// Test 2: sysinfo --cpu
	rootCmd.SetArgs([]string{"sysinfo", "--cpu"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute sysinfo --cpu: %v", err)
	}
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}

	// Parse the Sysinfo response
	var cpuInfo def.Emp3r0rAgent
	if err := cbor.Unmarshal(msg.Response, &cpuInfo); err != nil {
		t.Fatalf("Failed to unmarshal sysinfo response: %v", err)
	}

	if cpuInfo.CPU == "" {
		t.Errorf("Expected CPU info, got empty string")
	}

	// process info shouldn't be set
	if cpuInfo.Process != nil {
		t.Errorf("Did not expect Process info in granular output, got: %+v", cpuInfo.Process)
	}
	mockConn.Reset()
}
