package operator

// generate_test.go — tests for MakeConfig flag handling.
// Proxychain tests have been removed; the proxychain module is gone.
// P2P/mesh tests are integration tests deferred to manual verification.

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
	os.WriteFile(live.EmpConfigFile, data, 0o600)

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

func TestMakeConfig_AllFlags(t *testing.T) {
	// Setup temp config file
	tmpFile, err := os.CreateTemp("", "emp3r0r_flags_test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Mock Transport Paths
	tmpDir, _ := os.MkdirTemp("", "emp3r0r_operator_test_flags")
	defer os.RemoveAll(tmpDir)

	transport.CaCrtFile = filepath.Join(tmpDir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(tmpDir, "ca-key.pem")
	transport.ServerCrtFile = filepath.Join(tmpDir, "server-cert.pem")
	transport.ServerKeyFile = filepath.Join(tmpDir, "server-key.pem")
	transport.OperatorCaCrtFile = filepath.Join(tmpDir, "op-ca-cert.pem")
	transport.OperatorServerCrtFile = filepath.Join(tmpDir, "op-server-cert.pem")
	transport.OperatorServerKeyFile = filepath.Join(tmpDir, "op-server-key.pem")
	transport.EmpWorkSpace = tmpDir

	// Generate required certs to bypass checks
	_, _ = transport.GenCerts(nil, transport.CaCrtFile, transport.CaKeyFile, "", "", true)
	_, _ = transport.GenCerts([]string{"127.0.0.1", "10.0.0.1"}, transport.ServerCrtFile, transport.ServerKeyFile, transport.CaKeyFile, transport.CaCrtFile, false)
	_, _ = transport.GenCerts([]string{"127.0.0.1"}, transport.OperatorServerCrtFile, transport.OperatorServerKeyFile, transport.CaKeyFile, transport.CaCrtFile, false)

	// Base config (mimics emp3r0r.json state)
	baseConfig := map[string]interface{}{
		"cc_address":              "127.0.0.1",
		"cc_host":                 "127.0.0.1",
		"cc_port":                 "1337",
		"agent_socks_server_port": "1338",
		"ssh_host_key":            "mock-key",
		"agent_uuid":              "mock-uuid",
		"enable_ncsi":             false,
		"use_kcp":                 false,
		"is_run_by_stager":        false,
		"cdn_proxy":               "",
		"doh_server":              "",
		"c2_transport_proxy":      "",
	}

	type testFlags map[string]string

	type checks struct {
		checkFunc func(*testing.T, *def.Config)
	}

	tests := []struct {
		name   string
		flags  testFlags
		checks checks
	}{
		// P2P / Mesh tests
		{
			name:  "P2P Silent Node",
			flags: testFlags{"p2p": "true", "peers": "1.2.3.4:51996"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.IsP2PEnabled {
					t.Errorf("Expected IsP2PEnabled=true")
				}
				if c.IsDirectC2Enabled {
					t.Errorf("Expected IsDirectC2Enabled=false for silent node")
				}
				if len(c.InitialPeers) == 0 {
					t.Errorf("Expected InitialPeers for silent node")
				}
			}},
		},
		{
			name:  "P2P Gateway (--p2p --direct-c2)",
			flags: testFlags{"p2p": "true", "direct-c2": "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.IsP2PEnabled {
					t.Errorf("Expected IsP2PEnabled=true")
				}
			}},
		},

		// NCSI Tests
		{
			name:  "NCSI Enabled via Flag",
			flags: testFlags{"ncsi": "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.EnableNCSI {
					t.Errorf("Expected NCSI Enabled, got Disabled")
				}
			}},
		},
		{
			name:  "NCSI Disabled (Default)",
			flags: testFlags{},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.EnableNCSI {
					t.Errorf("Expected NCSI Disabled, got Enabled")
				}
			}},
		},

		// KCP Tests
		{
			name:  "KCP Enabled via Flag",
			flags: testFlags{"kcp": "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.UseKCP {
					t.Errorf("Expected KCP Enabled, got Disabled")
				}
			}},
		},

		// Stager Tests
		{
			name:  "Stager Enabled via Flag",
			flags: testFlags{"stager": "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.IsRunByStager {
					t.Errorf("Expected Stager Enabled, got Disabled")
				}
			}},
		},

		// CC Address Tests
		{
			name:  "CC Address Override",
			flags: testFlags{"cc": "10.0.0.1"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.CCAddress != "10.0.0.1" {
					t.Errorf("Expected CCAddress 10.0.0.1, got %s", c.CCAddress)
				}
			}},
		},

		// CDN Proxy Tests
		{
			name:  "CDN Proxy Override",
			flags: testFlags{"cdn": "http://cdn.example.com"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.CDNProxy != "http://cdn.example.com" {
					t.Errorf("Expected CDNProxy http://cdn.example.com, got %s", c.CDNProxy)
				}
			}},
		},

		// C2 Transport Proxy Tests
		{
			name:  "C2 Transport Proxy Override",
			flags: testFlags{"proxy": "socks5://1.2.3.4:1080"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.C2TransportProxy != "socks5://1.2.3.4:1080" {
					t.Errorf("Expected C2TransportProxy socks5://1.2.3.4:1080, got %s", c.C2TransportProxy)
				}
			}},
		},

		// DoH Server Tests
		{
			name:  "DoH Server Override",
			flags: testFlags{"doh": "https://doh.example.com"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.DoHServer != "https://doh.example.com" {
					t.Errorf("Expected DoHServer https://doh.example.com, got %s", c.DoHServer)
				}
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Write config (Reset base state)
			data, _ := json.Marshal(baseConfig)
			os.WriteFile(live.EmpConfigFile, data, 0o600)

			// 2. Setup Command
			cmd := &cobra.Command{}
			cmd.Flags().BoolP("p2p", "", false, "Enable P2P mesh networking")
			cmd.Flags().BoolP("direct-c2", "", false, "Gateway mode")
			cmd.Flags().StringSlice("peers", []string{}, "")
			cmd.Flags().String("cc", "", "")
			cmd.Flags().String("cdn", "", "")
			cmd.Flags().String("proxy", "", "")
			cmd.Flags().String("doh", "", "")
			cmd.Flags().Bool("ncsi", false, "")
			cmd.Flags().Bool("kcp", false, "")
			cmd.Flags().Bool("stager", false, "")

			// Set flags if specified
			for flagName, flagValue := range tc.flags {
				err := cmd.Flags().Set(flagName, flagValue)
				if err != nil {
					t.Fatalf("Failed to set flag %s: %v", flagName, err)
				}
			}

			// Reset RuntimeConfig
			live.RuntimeConfig = &def.Config{}
			live.IsServer = true

			// 3. Run MakeConfig
			err = MakeConfig(cmd)
			if err != nil {
				t.Fatalf("MakeConfig failed: %v", err)
			}

			// 4. Run Checks
			tc.checks.checkFunc(t, live.RuntimeConfig)
		})
	}
}
