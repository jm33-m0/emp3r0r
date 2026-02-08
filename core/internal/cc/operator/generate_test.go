package operator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/spf13/cobra"
)

func TestMakeConfig_PreservesPaths(t *testing.T) {
	// Setup temp config file
	tmpFile, err := os.CreateTemp("", "emp3r0r_paths.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Pre-existing random paths
	expectedPrefix := "pre_existing_prefix"
	expectedCheckin := "pre_existing_checkin"
	expectedMsg := "pre_existing_msg"

	// Mock Transport Paths to avoid permission issues or pollution
	tmpDir, _ := os.MkdirTemp("", "emp3r0r_operator_test_gen")
	defer os.RemoveAll(tmpDir)

	transport.CaCrtFile = filepath.Join(tmpDir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(tmpDir, "ca-key.pem")
	transport.ServerCrtFile = filepath.Join(tmpDir, "server-cert.pem")
	transport.ServerKeyFile = filepath.Join(tmpDir, "server-key.pem")
	transport.OperatorCaCrtFile = filepath.Join(tmpDir, "ca-cert.pem") // simplified
	transport.OperatorServerCrtFile = filepath.Join(tmpDir, "server-cert.pem")
	transport.OperatorServerKeyFile = filepath.Join(tmpDir, "server-key.pem")
	transport.EmpWorkSpace = tmpDir

	// Generate required certs
	_, _ = transport.GenCerts(nil, transport.CaCrtFile, transport.CaKeyFile, "", "", true)
	_, _ = transport.GenCerts([]string{"127.0.0.1"}, transport.ServerCrtFile, transport.ServerKeyFile, transport.CaKeyFile, transport.CaCrtFile, false)
	_, _ = transport.GenCerts([]string{"127.0.0.1"}, transport.OperatorServerCrtFile, transport.OperatorServerKeyFile, transport.CaKeyFile, transport.CaCrtFile, false)

	existingConfig := map[string]interface{}{
		"cc_address":              "127.0.0.1",
		"cc_host":                 "127.0.0.1",
		"agent_socks_server_port": "12345",
		"c2_prefix":               expectedPrefix,
		"checkin_path":            expectedCheckin,
		"msg_path":                expectedMsg,
	}
	data, _ := json.Marshal(existingConfig)
	os.WriteFile(live.EmpConfigFile, data, 0600)

	// Mock cobra command with NO flags (defaults)
	cmd := &cobra.Command{}

	// Reset live.RuntimeConfig to empty state to simulate fresh run
	live.RuntimeConfig = &def.Config{}
	live.IsServer = true // ensure we don't skip cert logic if needed

	// Run MakeConfig via CmdGenerateAgent logic (simulated)
	// MakeConfig is in internal/cc/operator/generate.go
	err = MakeConfig(cmd)
	if err != nil {
		t.Fatalf("MakeConfig failed: %v", err)
	}

	// Verify live.RuntimeConfig has the paths from file
	if live.RuntimeConfig.C2Prefix != expectedPrefix {
		t.Errorf("C2Prefix mismatch. Got %s, expected %s", live.RuntimeConfig.C2Prefix, expectedPrefix)
	}
	if live.RuntimeConfig.CheckInPath != expectedCheckin {
		t.Errorf("CheckInPath mismatch. Got %s, expected %s", live.RuntimeConfig.CheckInPath, expectedCheckin)
	}
	if live.RuntimeConfig.MsgPath != expectedMsg {
		t.Errorf("MsgPath mismatch. Got %s, expected %s", live.RuntimeConfig.MsgPath, expectedMsg)
	}
}
