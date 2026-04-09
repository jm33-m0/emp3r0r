package config

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// shadow structs for JSON I/O to avoid putting JSON tags in shared def package
type jsonMalleableHTTPConfig struct {
	C2Path        string            `json:"c2_path"`
	SessionHeader string            `json:"session_header"`
	SessionValue  string            `json:"session_value"`
	InitHeader    string            `json:"init_header"`
	InitValue     string            `json:"init_value"`
	CloseHeader   string            `json:"close_header"`
	CloseValue    string            `json:"close_value"`
	CustomHeaders map[string]string `json:"custom_headers"`
}

type jsonC2Routing struct {
	Checkin string `json:"checkin"`
	Msg     string `json:"msg"`
	FTP     string `json:"ftp"`
	WWW     string `json:"www"`
	Proxy   string `json:"proxy"`
}

type jsonConfig struct {
	CCAddress                 string                  `json:"cc_address"`
	CCHost                    string                  `json:"cc_host"`
	CCPort                    string                  `json:"cc_port"`
	AgentSocksServerPort      string                  `json:"agent_socks_server_port"`
	AgentSocksTimeout         int                     `json:"agent_socks_timeout"`
	StagerHTTPListenerPort    string                  `json:"stager_http_listener_port"`
	Password                  string                  `json:"password"`
	ShadowsocksLocalSocksPort string                  `json:"shadowsocks_local_socks_port"`
	ShadowsocksServerPort     string                  `json:"shadowsocks_server_port"`
	KCPServerPort             string                  `json:"kcp_server_port"`
	KCPClientPort             string                  `json:"kcp_client_port"`
	UseKCP                    bool                    `json:"use_kcp"`
	EnableNCSI                bool                    `json:"enable_ncsi"`
	SSHHostKey                string                  `json:"ssh_host_key"`
	Bring2CCReverseProxyPort  string                  `json:"bring2cc_reverse_proxy_port"`
	SSHDShellPort             string                  `json:"sshd_shell_port"`
	MeshGossipPort            string                  `json:"mesh_gossip_port"`
	PreflightEnabled          bool                    `json:"preflight_enabled"`
	PreflightURL              string                  `json:"preflight_url"`
	PreflightMethod           string                  `json:"preflight_method"`
	PreflightHeaders          map[string]string       `json:"preflight_headers"`
	PreflightIntervalMin      int                     `json:"preflight_interval_min"`
	PreflightIntervalMax      int                     `json:"preflight_interval_max"`
	CAPEM                     string                  `json:"ca_pem"`
	CAFingerprint             string                  `json:"ca_fingerprint"`
	C2TransportProxy          string                  `json:"c2_transport_proxy"`
	CDNProxy                  string                  `json:"cdn_proxy"`
	DoHServer                 string                  `json:"doh_server"`
	AgentUUID                 string                  `json:"agent_uuid"`
	AgentUUIDSig              string                  `json:"agent_uuid_sig"`
	AgentTag                  string                  `json:"agent_tag"`
	CCTimeout                 int                     `json:"cc_timeout"`
	PaddingMin                int                     `json:"padding_min"`
	PaddingMax                int                     `json:"padding_max"`
	Jitter                    int                     `json:"jitter"`
	PollInterval              int                     `json:"poll_interval"`
	ModulePath                string                  `json:"module_path"`
	IsRunByStager             bool                    `json:"is_run_by_stager"`
	MachineID                 string                  `json:"machine_id"`
	InitialPeers              []string                `json:"initial_peers"`
	IsP2PEnabled              bool                    `json:"is_p2p_enabled"`
	IsDirectC2Enabled         bool                    `json:"is_direct_c2_enabled"`
	P2PTransport              string                  `json:"p2p_transport"`
	CamouflageCertOrg         string                  `json:"camouflage_cert_org"`
	CamouflageCertCN          string                  `json:"camouflage_cert_cn"`
	C2Routes                  jsonC2Routing           `json:"c2_routes"`
	C2ChannelMode             string                  `json:"c2_channel_mode"`
	CCHTTPPort                string                  `json:"cc_http_port"`
	MalleableC2               jsonMalleableHTTPConfig `json:"malleable_c2"`
}

// readJSONConfig read runtime variables from JSON, and apply them
func readJSONConfig(jsonData []byte, config_to_write *def.Config) (err error) {
	// parse the json
	var raw map[string]any
	err = json.Unmarshal(jsonData, &raw)
	if err != nil {
		return fmt.Errorf("failed to parse JSON config: %v", err)
	}

	// Helper to safely extract string
	getString := func(key string) string {
		if val, ok := raw[key].(string); ok {
			return val
		}
		return ""
	}

	// Helper to safely extract int
	getInt := func(key string) int {
		if val, ok := raw[key].(float64); ok {
			return int(val)
		}
		return 0
	}

	// Helper to safely extract bool
	getBool := func(key string) bool {
		if val, ok := raw[key].(bool); ok {
			return val
		}
		return false
	}

	// Helper to safely extract string values from an object map.
	getStringFromMap := func(obj map[string]any, keys ...string) string {
		for _, key := range keys {
			if val, ok := obj[key].(string); ok {
				return val
			}
		}
		return ""
	}

	// Helper to safely extract string slice
	getStringSlice := func(key string) []string {
		if val, ok := raw[key].([]any); ok {
			var res []string
			for _, v := range val {
				if s, ok := v.(string); ok {
					res = append(res, s)
				}
			}
			return res
		}
		// Also try PascalCase
		if key == "initial_peers" {
			if val, ok := raw["InitialPeers"].([]any); ok {
				var res []string
				for _, v := range val {
					if s, ok := v.(string); ok {
						res = append(res, s)
					}
				}
				return res
			}
		}
		return nil
	}

	config_to_write.CCAddress = getString("cc_address")
	config_to_write.CCHost = getString("cc_host")
	config_to_write.CCPort = getString("cc_port")
	config_to_write.AgentSocksServerPort = getString("agent_socks_server_port")
	config_to_write.AgentSocksTimeout = getInt("agent_socks_timeout")
	config_to_write.StagerHTTPListenerPort = getString("stager_http_listener_port")
	config_to_write.Password = getString("password")
	config_to_write.ShadowsocksLocalSocksPort = getString("shadowsocks_local_socks_port")
	config_to_write.ShadowsocksServerPort = getString("shadowsocks_server_port")
	config_to_write.KCPServerPort = getString("kcp_server_port")
	config_to_write.KCPClientPort = getString("kcp_client_port")
	config_to_write.UseKCP = getBool("use_kcp")
	config_to_write.EnableNCSI = getBool("enable_ncsi")

	if val, ok := raw["ssh_host_key"].(string); ok {
		config_to_write.SSHHostKey = []byte(val)
	}

	config_to_write.Bring2CCReverseProxyPort = getString("bring2cc_reverse_proxy_port")
	config_to_write.SSHDShellPort = getString("sshd_shell_port")
	config_to_write.MeshGossipPort = getString("mesh_gossip_port")
	config_to_write.PreflightEnabled = getBool("preflight_enabled")
	config_to_write.PreflightURL = getString("preflight_url")
	config_to_write.PreflightMethod = getString("preflight_method")
	if val, ok := raw["preflight_headers"].(map[string]any); ok {
		config_to_write.PreflightHeaders = make(map[string]string)
		for k, v := range val {
			if strV, ok := v.(string); ok {
				config_to_write.PreflightHeaders[k] = strV
			}
		}
	}
	config_to_write.CAPEM = getString("ca_pem")
	config_to_write.CAFingerprint = getString("ca_fingerprint")
	config_to_write.C2TransportProxy = getString("c2_transport_proxy")
	config_to_write.CDNProxy = getString("cdn_proxy")
	config_to_write.DoHServer = getString("doh_server")
	if val := getString("agent_uuid"); val != "" {
		config_to_write.AgentUUID = val
	} else {
		config_to_write.AgentUUID = uuid.NewString()
	}
	config_to_write.AgentUUIDSig = getString("agent_uuid_sig")
	config_to_write.AgentTag = getString("agent_tag")
	config_to_write.CCTimeout = getInt("cc_timeout")

	// Payload-length malleability
	config_to_write.PaddingMin = getInt("padding_min")
	config_to_write.PaddingMax = getInt("padding_max")
	config_to_write.Jitter = getInt("jitter")
	config_to_write.PollInterval = getInt("poll_interval")
	if config_to_write.PollInterval == 0 {
		config_to_write.PollInterval = getInt("PollInterval")
	}
	config_to_write.ModulePath = getString("module_path")
	config_to_write.IsRunByStager = getBool("is_run_by_stager")
	if val, ok := raw["c2_routes"].(map[string]any); ok {
		config_to_write.C2Routes.Checkin = getStringFromMap(val, "checkin", "Checkin")
		config_to_write.C2Routes.Msg = getStringFromMap(val, "msg", "Msg")
		config_to_write.C2Routes.FTP = getStringFromMap(val, "ftp", "FTP")
		config_to_write.C2Routes.WWW = getStringFromMap(val, "www", "WWW")
		config_to_write.C2Routes.Proxy = getStringFromMap(val, "proxy", "Proxy")
	} else if val, ok := raw["C2Routes"].(map[string]any); ok {
		config_to_write.C2Routes.Checkin = getStringFromMap(val, "checkin", "Checkin")
		config_to_write.C2Routes.Msg = getStringFromMap(val, "msg", "Msg")
		config_to_write.C2Routes.FTP = getStringFromMap(val, "ftp", "FTP")
		config_to_write.C2Routes.WWW = getStringFromMap(val, "www", "WWW")
		config_to_write.C2Routes.Proxy = getStringFromMap(val, "proxy", "Proxy")
	}
	def.NormalizeC2Routes(&config_to_write.C2Routes)
	config_to_write.C2ChannelMode = getString("c2_channel_mode")
	if config_to_write.C2ChannelMode == "" {
		config_to_write.C2ChannelMode = getString("C2ChannelMode")
	}
	if config_to_write.C2ChannelMode == "" {
		config_to_write.C2ChannelMode = def.C2ChannelModeDefault
	}
	config_to_write.CCHTTPPort = getString("cc_http_port")
	if config_to_write.CCHTTPPort == "" {
		config_to_write.CCHTTPPort = getString("CCHTTPPort")
	}

	// Malleable C2
	loadMalleableC2 := func(val map[string]any) {
		config_to_write.MalleableC2.C2Path = getStringFromMap(val, "c2_path", "C2Path")
		config_to_write.MalleableC2.SessionHeader = getStringFromMap(val, "session_header", "SessionHeader")
		config_to_write.MalleableC2.SessionValue = getStringFromMap(val, "session_value", "SessionValue")
		config_to_write.MalleableC2.InitHeader = getStringFromMap(val, "init_header", "InitHeader")
		config_to_write.MalleableC2.InitValue = getStringFromMap(val, "init_value", "InitValue")
		config_to_write.MalleableC2.CloseHeader = getStringFromMap(val, "close_header", "CloseHeader")
		config_to_write.MalleableC2.CloseValue = getStringFromMap(val, "close_value", "CloseValue")
		customHeaderKey := "custom_headers"
		if _, ok := val[customHeaderKey].(map[string]any); !ok {
			customHeaderKey = "CustomHeaders"
		}
		if headers, ok := val[customHeaderKey].(map[string]any); ok {
			config_to_write.MalleableC2.CustomHeaders = make(map[string]string)
			for k, v := range headers {
				if strV, ok := v.(string); ok {
					config_to_write.MalleableC2.CustomHeaders[k] = strV
				}
			}
		}
	}
	if val, ok := raw["malleable_c2"].(map[string]any); ok {
		loadMalleableC2(val)
	} else if val, ok := raw["MalleableC2"].(map[string]any); ok {
		loadMalleableC2(val)
	}

	// Preflight Intervals
	config_to_write.PreflightIntervalMin = getInt("preflight_interval_min")
	if config_to_write.PreflightIntervalMin == 0 {
		config_to_write.PreflightIntervalMin = getInt("PreflightIntervalMin")
	}
	config_to_write.PreflightIntervalMax = getInt("preflight_interval_max")
	if config_to_write.PreflightIntervalMax == 0 {
		config_to_write.PreflightIntervalMax = getInt("PreflightIntervalMax")
	}

	// P2P / Mesh
	config_to_write.IsP2PEnabled = getBool("is_p2p_enabled")
	if !config_to_write.IsP2PEnabled {
		config_to_write.IsP2PEnabled = getBool("IsP2PEnabled")
	}
	config_to_write.IsDirectC2Enabled = getBool("is_direct_c2_enabled")
	if !config_to_write.IsDirectC2Enabled {
		config_to_write.IsDirectC2Enabled = getBool("IsDirectC2Enabled")
	}
	config_to_write.P2PTransport = getString("p2p_transport")
	if config_to_write.P2PTransport == "" {
		config_to_write.P2PTransport = getString("P2PTransport")
	}
	config_to_write.CamouflageCertOrg = getString("camouflage_cert_org")
	if config_to_write.CamouflageCertOrg == "" {
		config_to_write.CamouflageCertOrg = getString("CamouflageCertOrg")
	}
	config_to_write.CamouflageCertCN = getString("camouflage_cert_cn")
	if config_to_write.CamouflageCertCN == "" {
		config_to_write.CamouflageCertCN = getString("CamouflageCertCN")
	}
	config_to_write.InitialPeers = getStringSlice("initial_peers")

	// Identity
	config_to_write.MachineID = getString("machine_id")
	if config_to_write.MachineID == "" {
		config_to_write.MachineID = getString("MachineID")
	}
	config_to_write.ModulePath = getString("module_path")
	if config_to_write.ModulePath == "" {
		config_to_write.ModulePath = getString("ModulePath")
	}

	// Double-check with shadow struct unmarshaling to ensure NO field is missed
	// This is the source of truth for loading, while keeping backward compatibility above
	var jCfg jsonConfig
	if err := json.Unmarshal(jsonData, &jCfg); err == nil {
		// Only override if not empty/zero (basic heuristic)
		if jCfg.CCAddress != "" { config_to_write.CCAddress = jCfg.CCAddress }
		if jCfg.CCHost != "" { config_to_write.CCHost = jCfg.CCHost }
		if jCfg.CCPort != "" { config_to_write.CCPort = jCfg.CCPort }
		if jCfg.AgentSocksServerPort != "" { config_to_write.AgentSocksServerPort = jCfg.AgentSocksServerPort }
		if jCfg.AgentSocksTimeout != 0 { config_to_write.AgentSocksTimeout = jCfg.AgentSocksTimeout }
		if jCfg.StagerHTTPListenerPort != "" { config_to_write.StagerHTTPListenerPort = jCfg.StagerHTTPListenerPort }
		if jCfg.Password != "" { config_to_write.Password = jCfg.Password }
		if jCfg.ShadowsocksLocalSocksPort != "" { config_to_write.ShadowsocksLocalSocksPort = jCfg.ShadowsocksLocalSocksPort }
		if jCfg.ShadowsocksServerPort != "" { config_to_write.ShadowsocksServerPort = jCfg.ShadowsocksServerPort }
		if jCfg.KCPServerPort != "" { config_to_write.KCPServerPort = jCfg.KCPServerPort }
		if jCfg.KCPClientPort != "" { config_to_write.KCPClientPort = jCfg.KCPClientPort }
		if jCfg.UseKCP { config_to_write.UseKCP = jCfg.UseKCP }
		if jCfg.EnableNCSI { config_to_write.EnableNCSI = jCfg.EnableNCSI }
		if jCfg.SSHHostKey != "" { config_to_write.SSHHostKey = []byte(jCfg.SSHHostKey) }
		if jCfg.Bring2CCReverseProxyPort != "" { config_to_write.Bring2CCReverseProxyPort = jCfg.Bring2CCReverseProxyPort }
		if jCfg.SSHDShellPort != "" { config_to_write.SSHDShellPort = jCfg.SSHDShellPort }
		if jCfg.MeshGossipPort != "" { config_to_write.MeshGossipPort = jCfg.MeshGossipPort }
		if jCfg.PreflightEnabled { config_to_write.PreflightEnabled = jCfg.PreflightEnabled }
		if jCfg.PreflightURL != "" { config_to_write.PreflightURL = jCfg.PreflightURL }
		if jCfg.PreflightMethod != "" { config_to_write.PreflightMethod = jCfg.PreflightMethod }
		if len(jCfg.PreflightHeaders) > 0 { config_to_write.PreflightHeaders = jCfg.PreflightHeaders }
		if jCfg.PreflightIntervalMin != 0 { config_to_write.PreflightIntervalMin = jCfg.PreflightIntervalMin }
		if jCfg.PreflightIntervalMax != 0 { config_to_write.PreflightIntervalMax = jCfg.PreflightIntervalMax }
		if jCfg.CAPEM != "" { config_to_write.CAPEM = jCfg.CAPEM }
		if jCfg.CAFingerprint != "" { config_to_write.CAFingerprint = jCfg.CAFingerprint }
		if jCfg.C2TransportProxy != "" { config_to_write.C2TransportProxy = jCfg.C2TransportProxy }
		if jCfg.CDNProxy != "" { config_to_write.CDNProxy = jCfg.CDNProxy }
		if jCfg.DoHServer != "" { config_to_write.DoHServer = jCfg.DoHServer }
		if jCfg.AgentUUID != "" { config_to_write.AgentUUID = jCfg.AgentUUID }
		if jCfg.AgentUUIDSig != "" { config_to_write.AgentUUIDSig = jCfg.AgentUUIDSig }
		if jCfg.AgentTag != "" { config_to_write.AgentTag = jCfg.AgentTag }
		if jCfg.CCTimeout != 0 { config_to_write.CCTimeout = jCfg.CCTimeout }
		if jCfg.PaddingMin != 0 { config_to_write.PaddingMin = jCfg.PaddingMin }
		if jCfg.PaddingMax != 0 { config_to_write.PaddingMax = jCfg.PaddingMax }
		if jCfg.Jitter != 0 { config_to_write.Jitter = jCfg.Jitter }
		if jCfg.PollInterval != 0 { config_to_write.PollInterval = jCfg.PollInterval }
		if jCfg.ModulePath != "" { config_to_write.ModulePath = jCfg.ModulePath }
		if jCfg.IsRunByStager { config_to_write.IsRunByStager = jCfg.IsRunByStager }
		if jCfg.MachineID != "" { config_to_write.MachineID = jCfg.MachineID }
		if len(jCfg.InitialPeers) > 0 { config_to_write.InitialPeers = jCfg.InitialPeers }
		if jCfg.IsP2PEnabled { config_to_write.IsP2PEnabled = jCfg.IsP2PEnabled }
		if jCfg.IsDirectC2Enabled { config_to_write.IsDirectC2Enabled = jCfg.IsDirectC2Enabled }
		if jCfg.P2PTransport != "" { config_to_write.P2PTransport = jCfg.P2PTransport }
		if jCfg.CamouflageCertOrg != "" { config_to_write.CamouflageCertOrg = jCfg.CamouflageCertOrg }
		if jCfg.CamouflageCertCN != "" { config_to_write.CamouflageCertCN = jCfg.CamouflageCertCN }
		if jCfg.C2Routes.Checkin != "" { config_to_write.C2Routes.Checkin = jCfg.C2Routes.Checkin }
		if jCfg.C2Routes.Msg != "" { config_to_write.C2Routes.Msg = jCfg.C2Routes.Msg }
		if jCfg.C2Routes.FTP != "" { config_to_write.C2Routes.FTP = jCfg.C2Routes.FTP }
		if jCfg.C2Routes.WWW != "" { config_to_write.C2Routes.WWW = jCfg.C2Routes.WWW }
		if jCfg.C2Routes.Proxy != "" { config_to_write.C2Routes.Proxy = jCfg.C2Routes.Proxy }
		if jCfg.C2ChannelMode != "" { config_to_write.C2ChannelMode = jCfg.C2ChannelMode }
		if jCfg.CCHTTPPort != "" { config_to_write.CCHTTPPort = jCfg.CCHTTPPort }
		
		// Malleable C2 from shadow struct
		if jCfg.MalleableC2.C2Path != "" { config_to_write.MalleableC2.C2Path = jCfg.MalleableC2.C2Path }
		if jCfg.MalleableC2.SessionHeader != "" { config_to_write.MalleableC2.SessionHeader = jCfg.MalleableC2.SessionHeader }
		if jCfg.MalleableC2.SessionValue != "" { config_to_write.MalleableC2.SessionValue = jCfg.MalleableC2.SessionValue }
		if jCfg.MalleableC2.InitHeader != "" { config_to_write.MalleableC2.InitHeader = jCfg.MalleableC2.InitHeader }
		if jCfg.MalleableC2.InitValue != "" { config_to_write.MalleableC2.InitValue = jCfg.MalleableC2.InitValue }
		if jCfg.MalleableC2.CloseHeader != "" { config_to_write.MalleableC2.CloseHeader = jCfg.MalleableC2.CloseHeader }
		if jCfg.MalleableC2.CloseValue != "" { config_to_write.MalleableC2.CloseValue = jCfg.MalleableC2.CloseValue }
		if len(jCfg.MalleableC2.CustomHeaders) > 0 { config_to_write.MalleableC2.CustomHeaders = jCfg.MalleableC2.CustomHeaders }
	}

	calculateReverseProxyPort := func() (string, error) {
		p, err := strconv.Atoi(config_to_write.AgentSocksServerPort)
		if err != nil {
			return "", fmt.Errorf("WTF? AgentSocksServerPort: %s: %v. Invalid JSON config, perhaps start over with a new config file?", config_to_write.AgentSocksServerPort, err)
		}

		// reverseProxyPort
		rProxyPortInt := p + 1
		return strconv.Itoa(rProxyPortInt), nil
	}
	config_to_write.Bring2CCReverseProxyPort, err = calculateReverseProxyPort()
	if err != nil {
		return err
	}

	// these variables are decided by other variables
	def.CCAddress = fmt.Sprintf("https://%s", config_to_write.CCAddress)
	def.DefaultShell = "/bin/bash" // Default to standard bash

	return
}
