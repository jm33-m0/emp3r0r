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
	tmpFile, err := os.CreateTemp("", "emp3r0r_proxy_test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Mock Transport Paths
	tmpDir, _ := os.MkdirTemp("", "emp3r0r_operator_test_proxy")
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
		"cc_address":                         "127.0.0.1",
		"cc_host":                            "127.0.0.1",
		"cc_port":                            "1337",
		"agent_socks_server_port":            "1338",
		"ssh_host_key":                       "mock-key",
		"agent_uuid":                         "mock-uuid",
		"proxy_chain_broadcast_interval_min": 30,
		"proxy_chain_broadcast_interval_max": 130, // Enabled in file
		"enable_ncsi":                        false,
		"use_kcp":                            false,
		"is_run_by_stager":                   false,
		"cdn_proxy":                          "",
		"doh_server":                         "",
		"c2_transport_proxy":                 "",
	}

	type fields struct {
		flagName  string
		flagValue string // "true", "false", or "string_value"
	}
	type checks struct {
		checkFunc func(*testing.T, *def.Config)
	}

	tests := []struct {
		name   string
		fields fields
		checks checks
	}{
		// ProxyChain Tests (Previous Bug Fix)
		{
			name:   "ProxyChain Default (Flag Not Set)",
			fields: fields{flagName: "", flagValue: ""}, // Not set
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.ProxyChainBroadcastIntervalMax != 0 {
					t.Errorf("Expected ProxyChain Disabled (0), got %d", c.ProxyChainBroadcastIntervalMax)
				}
			}},
		},
		{
			name:   "ProxyChain Explicitly Disabled",
			fields: fields{flagName: "proxychain", flagValue: "false"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.ProxyChainBroadcastIntervalMax != 0 {
					t.Errorf("Expected ProxyChain Disabled (0), got %d", c.ProxyChainBroadcastIntervalMax)
				}
			}},
		},
		{
			name:   "ProxyChain Explicitly Enabled",
			fields: fields{flagName: "proxychain", flagValue: "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.ProxyChainBroadcastIntervalMax == 0 {
					t.Errorf("Expected ProxyChain Enabled, but it was disabled")
				}
			}},
		},

		// NCSI Tests
		{
			name:   "NCSI Enabled via Flag",
			fields: fields{flagName: "ncsi", flagValue: "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.EnableNCSI {
					t.Errorf("Expected NCSI Enabled, got Disabled")
				}
			}},
		},
		{
			name:   "NCSI Disabled (Default)",
			fields: fields{flagName: "", flagValue: ""},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.EnableNCSI {
					t.Errorf("Expected NCSI Disabled, got Enabled")
				}
			}},
		},

		// KCP Tests
		{
			name:   "KCP Enabled via Flag",
			fields: fields{flagName: "kcp", flagValue: "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.UseKCP {
					t.Errorf("Expected KCP Enabled, got Disabled")
				}
			}},
		},

		// Stager Tests
		{
			name:   "Stager Enabled via Flag",
			fields: fields{flagName: "stager", flagValue: "true"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if !c.IsRunByStager {
					t.Errorf("Expected Stager Enabled, got Disabled")
				}
			}},
		},

		// CC Address Tests
		{
			name:   "CC Address Override",
			fields: fields{flagName: "cc", flagValue: "10.0.0.1"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.CCAddress != "10.0.0.1" {
					t.Errorf("Expected CCAddress 10.0.0.1, got %s", c.CCAddress)
				}
			}},
		},

		// CDN Proxy Tests
		{
			name:   "CDN Proxy Override",
			fields: fields{flagName: "cdn", flagValue: "http://cdn.example.com"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.CDNProxy != "http://cdn.example.com" {
					t.Errorf("Expected CDNProxy http://cdn.example.com, got %s", c.CDNProxy)
				}
			}},
		},

		// C2 Transport Proxy Tests
		{
			name:   "C2 Transport Proxy Override",
			fields: fields{flagName: "proxy", flagValue: "socks5://1.2.3.4:1080"},
			checks: checks{func(t *testing.T, c *def.Config) {
				if c.C2TransportProxy != "socks5://1.2.3.4:1080" {
					t.Errorf("Expected C2TransportProxy socks5://1.2.3.4:1080, got %s", c.C2TransportProxy)
				}
			}},
		},

		// DoH Server Tests
		{
			name:   "DoH Server Override",
			fields: fields{flagName: "doh", flagValue: "https://doh.example.com"},
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
			cmd.Flags().BoolP("proxychain", "", false, "Enable auto proxy chain")
			cmd.Flags().IntP("proxychain-wait-min", "", 0, "")
			cmd.Flags().IntP("proxychain-wait-max", "", 0, "")
			cmd.Flags().String("cc", "", "")
			cmd.Flags().String("cdn", "", "")
			cmd.Flags().String("proxy", "", "")
			cmd.Flags().String("doh", "", "")
			cmd.Flags().Bool("ncsi", false, "")
			cmd.Flags().Bool("kcp", false, "")
			cmd.Flags().Bool("stager", false, "")

			// Set flags if specified
			if tc.fields.flagName != "" {
				err := cmd.Flags().Set(tc.fields.flagName, tc.fields.flagValue)
				if err != nil {
					t.Fatalf("Failed to set flag %s: %v", tc.fields.flagName, err)
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
