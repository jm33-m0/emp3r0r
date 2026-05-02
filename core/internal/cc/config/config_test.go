package config

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func TestInitConfigFile(t *testing.T) {
	// Initialize RuntimeConfig if it's nil
	if live.RuntimeConfig == nil {
		live.RuntimeConfig = &def.Config{}
	}

	// Setup temp file for config
	tmpConfigFile, err := os.CreateTemp("", "emp3r0r.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpConfigFile.Name())
	tmpConfigFile.Close()

	// Save original EmpConfigFile and restore it after test
	originalEmpConfigFile := live.EmpConfigFile
	defer func() { live.EmpConfigFile = originalEmpConfigFile }()
	live.EmpConfigFile = tmpConfigFile.Name()

	// Setup temp file for CA Key
	tmpKeyFile, err := os.CreateTemp("", "ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	tmpKeyFile.Close()
	defer os.Remove(tmpKeyFile.Name())

	// Create temp file for CA cert
	tmpCrtFile, err := os.CreateTemp("", "emp3r0r-ca-crt-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	tmpCrtFile.Close()
	defer os.Remove(tmpCrtFile.Name())

	// Generate CA cert and key using transport.GenCerts
	_, err = transport.GenCerts(nil, tmpCrtFile.Name(), tmpKeyFile.Name(), "", "", true)
	if err != nil {
		t.Fatalf("GenCerts failed: %v", err)
	}

	// Save original CaKeyFile and restore it after test
	originalCaKeyFile := transport.CaKeyFile
	defer func() { transport.CaKeyFile = originalCaKeyFile }()
	transport.CaKeyFile = tmpKeyFile.Name()

	// Save original CaCrtFile and restore it after test
	originalCaCrtFile := transport.CaCrtFile
	defer func() { transport.CaCrtFile = originalCaCrtFile }()
	transport.CaCrtFile = tmpCrtFile.Name()

	ccHost := "127.0.0.1"
	live.RuntimeConfig.CCHTTPPort = "12345"
	live.RuntimeConfig.CCH2Port = "12346"
	err = InitConfigFile(ccHost)
	if err != nil {
		t.Fatalf("InitConfigFile failed: %v", err)
	}

	// Verify fields
	if live.RuntimeConfig.CCAddress != ccHost {
		t.Errorf("Expected CCAddress %s, got %s", ccHost, live.RuntimeConfig.CCAddress)
	}

	// Check if ports are valid integers
	checkPort := func(name, portStr string) {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Errorf("%s is not a valid integer: %s", name, portStr)
			return
		}
		if port < 1025 || port > 65534 {
			t.Errorf("%s is out of range (1025-65534): %d", name, port)
		}
	}

	checkPort("CCPort", live.RuntimeConfig.CCH2Port)
	checkPort("AgentSocksServerPort", live.RuntimeConfig.AgentSocksServerPort)
	checkPort("SSHDShellPort", live.RuntimeConfig.SSHDShellPort)

	// Check if UUID is set
	if live.RuntimeConfig.AgentUUID == "" {
		t.Error("AgentUUID is empty")
	}

	// Check if SSHHostKey is generated
	if len(live.RuntimeConfig.SSHHostKey) == 0 {
		t.Error("SSHHostKey is empty")
	}

	// Check if AgentUUIDSig is set
	if live.RuntimeConfig.AgentUUIDSig == "" {
		t.Error("AgentUUIDSig is empty")
	}
}

func TestSaveConfigJSON(t *testing.T) {
	// Setup temp file for config
	tmpFile, err := os.CreateTemp("", "emp3r0r.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Save original EmpConfigFile and restore it after test
	originalEmpConfigFile := live.EmpConfigFile
	defer func() { live.EmpConfigFile = originalEmpConfigFile }()

	live.EmpConfigFile = tmpFile.Name()

	// Setup a dummy RuntimeConfig
	live.RuntimeConfig = &def.Config{
		CCAddress:            "test.example.com",
		CCH2Port:             "9999",
		AgentSocksServerPort: "1080",
		PaddingMin:           512,
		PaddingMax:           4096,
		Jitter:               10,
		C2ChannelMode:        def.C2ChannelModeH2Conn,
	}

	// Test SaveConfigJSON
	err = SaveConfigJSON()
	if err != nil {
		t.Fatalf("SaveConfigJSON failed: %v", err)
	}

	// Read back the file
	data, err := os.ReadFile(live.EmpConfigFile)
	if err != nil {
		t.Fatalf("Failed to read saved config file: %v", err)
	}

	var loadedConfig def.Config
	err = readJSONConfig(data, &loadedConfig)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}

	if loadedConfig.CCAddress != "test.example.com" {
		t.Errorf("Loaded config mismatch. Expected CCAddress 'test.example.com', got '%s'", loadedConfig.CCAddress)
	}
	if loadedConfig.CCH2Port != "9999" {
		t.Errorf("Loaded config mismatch. Expected CCPort '9999', got '%s'", loadedConfig.CCH2Port)
	}
	if loadedConfig.PaddingMin != 512 {
		t.Errorf("Loaded config mismatch. Expected PaddingMin 512, got %d", loadedConfig.PaddingMin)
	}
	if loadedConfig.PaddingMax != 4096 {
		t.Errorf("Loaded config mismatch. Expected PaddingMax 4096, got %d", loadedConfig.PaddingMax)
	}
	if loadedConfig.C2ChannelMode != def.C2ChannelModeH2Conn {
		t.Errorf("Loaded config mismatch. Expected C2ChannelMode %s, got %s", def.C2ChannelModeH2Conn, loadedConfig.C2ChannelMode)
	}
}

func TestSaveAndLoadConfigJSON(t *testing.T) {
	// Initialize RuntimeConfig
	live.RuntimeConfig = &def.Config{
		CCAddress:            "5.6.7.8",
		CCH2Port:             "5678",
		AgentSocksServerPort: "9090",
		Password:             "another_secret",
		C2ChannelMode:        def.C2ChannelModeH2Conn,
	}

	// Mock EmpConfigFile
	tmpFile, err := os.CreateTemp("", "emp3r0r_save_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Save config
	err = SaveConfigJSON()
	if err != nil {
		t.Fatalf("SaveConfigJSON failed: %v", err)
	}

	// Read the file content to check format (should be snake_case)
	content, err := os.ReadFile(live.EmpConfigFile)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}

	// Check if keys are snake_case
	var raw map[string]any
	err = json.Unmarshal(content, &raw)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved JSON: %v", err)
	}

	if _, ok := raw["cc_address"]; !ok {
		t.Errorf("Saved JSON does not contain 'cc_address' key. Content: %s", string(content))
	}
	if _, ok := raw["CCAddress"]; ok {
		t.Errorf("Saved JSON contains 'CCAddress' key (should be snake_case). Content: %s", string(content))
	}
}

func TestReadJSONConfigLoadsC2Routes(t *testing.T) {
	jsonData := []byte(`{
		"cc_address": "127.0.0.1",
		"cc_port": "12345",
		"agent_socks_server_port": "1080",
		"c2_routes": {
			"Checkin": "route-checkin",
			"Msg": "route-msg",
			"FTP": "route-ftp",
			"WWW": "route-www",
			"Proxy": "route-proxy"
		}
	}`)

	loaded := &def.Config{}
	err := readJSONConfig(jsonData, loaded)
	if err != nil {
		t.Fatalf("readJSONConfig failed: %v", err)
	}

	if loaded.C2Routes.Checkin != "route-checkin" {
		t.Errorf("Expected C2Routes.Checkin route-checkin, got %s", loaded.C2Routes.Checkin)
	}
	if loaded.C2Routes.Msg != "route-msg" {
		t.Errorf("Expected C2Routes.Msg route-msg, got %s", loaded.C2Routes.Msg)
	}
	if loaded.C2Routes.FTP != "route-ftp" {
		t.Errorf("Expected C2Routes.FTP route-ftp, got %s", loaded.C2Routes.FTP)
	}
	if loaded.C2Routes.WWW != "route-www" {
		t.Errorf("Expected C2Routes.WWW route-www, got %s", loaded.C2Routes.WWW)
	}
	if loaded.C2Routes.Proxy != "route-proxy" {
		t.Errorf("Expected C2Routes.Proxy route-proxy, got %s", loaded.C2Routes.Proxy)
	}
}

func TestReadJSONConfigLoadsPlainHTTP(t *testing.T) {
	jsonData := []byte(`{
		"cc_address": "127.0.0.1",
		"cc_port": "12345",
		"agent_socks_server_port": "1080",
		"cc_http_port": "8080",
		"c2_channel_mode": "http_poll",
		"malleable_c2": {
			"c2_path": "/test-path",
			"session_header": "X-Session-ID",
			"session_value": "sid-%s",
			"custom_headers": {
				"User-Agent": "Test-UA",
				"X-Custom": "Value"
			}
		}
	}`)

	loaded := &def.Config{}
	err := readJSONConfig(jsonData, loaded)
	if err != nil {
		t.Fatalf("readJSONConfig failed: %v", err)
	}

	if loaded.CCHTTPPort != "8080" {
		t.Errorf("Expected CCHTTPPort 8080, got %s", loaded.CCHTTPPort)
	}
	if loaded.C2ChannelMode != "http_poll" {
		t.Errorf("Expected C2ChannelMode http_poll, got %s", loaded.C2ChannelMode)
	}
	if loaded.MalleableC2.C2Path != "/test-path" {
		t.Errorf("Expected MalleableC2.C2Path /test-path, got %s", loaded.MalleableC2.C2Path)
	}
	if loaded.MalleableC2.SessionHeader != "X-Session-ID" {
		t.Errorf("Expected MalleableC2.SessionHeader X-Session-ID, got %s", loaded.MalleableC2.SessionHeader)
	}
	if loaded.MalleableC2.CustomHeaders["User-Agent"] != "Test-UA" {
		t.Errorf("Expected User-Agent Test-UA, got %s", loaded.MalleableC2.CustomHeaders["User-Agent"])
	}
}

func TestReadJSONConfigFullCoverage(t *testing.T) {
	jsonData := []byte(`{
		"cc_address": "10.0.0.1",
		"cc_port": "443",
		"agent_socks_server_port": "1080",
		"preflight_interval_min": 60,
		"preflight_interval_max": 300,
		"is_p2p_enabled": true,
		"is_direct_c2_enabled": false,
		"p2p_transport": "kcp",
		"persistent_router": true,
		"camouflage_cert_org": "MyOrg",
		"camouflage_cert_cn": "www.google.com",
		"initial_peers": ["1.1.1.1:51996", "2.2.2.2:51996"],
		"machine_id": "test-machine",
		"module_path": "/tmp/test"
	}`)

	loaded := &def.Config{}
	err := readJSONConfig(jsonData, loaded)
	if err != nil {
		t.Fatalf("readJSONConfig failed: %v", err)
	}

	if loaded.PreflightIntervalMin != 60 {
		t.Errorf("Expected PreflightIntervalMin 60, got %d", loaded.PreflightIntervalMin)
	}
	if loaded.PreflightIntervalMax != 300 {
		t.Errorf("Expected PreflightIntervalMax 300, got %d", loaded.PreflightIntervalMax)
	}
	if !loaded.IsP2PEnabled {
		t.Errorf("Expected IsP2PEnabled true, got false")
	}
	if loaded.IsDirectC2Enabled {
		t.Errorf("Expected IsDirectC2Enabled false, got true")
	}
	if !loaded.PersistentRouter {
		t.Errorf("Expected PersistentRouter true, got false")
	}
	if loaded.P2PTransport != "kcp" {
		t.Errorf("Expected P2PTransport kcp, got %s", loaded.P2PTransport)
	}
	if loaded.CamouflageCertOrg != "MyOrg" {
		t.Errorf("Expected CamouflageCertOrg MyOrg, got %s", loaded.CamouflageCertOrg)
	}
	if loaded.CamouflageCertCN != "www.google.com" {
		t.Errorf("Expected CamouflageCertCN www.google.com, got %s", loaded.CamouflageCertCN)
	}
	if len(loaded.InitialPeers) != 2 || loaded.InitialPeers[0] != "1.1.1.1:51996" {
		t.Errorf("Expected InitialPeers [1.1.1.1:51996, 2.2.2.2:51996], got %v", loaded.InitialPeers)
	}
	if loaded.MachineID != "test-machine" {
		t.Errorf("Expected MachineID test-machine, got %s", loaded.MachineID)
	}
	if loaded.ModulePath != "/tmp/test" {
		t.Errorf("Expected ModulePath /tmp/test, got %s", loaded.ModulePath)
	}
}
