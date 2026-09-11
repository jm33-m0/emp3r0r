package config

import (
	"encoding/json"
	"fmt"

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
	PersistentRouter          bool                    `json:"persistent_router"`
	OperatorIdleTimeout       int                     `json:"operator_idle_timeout"`
	P2PTransport              string                  `json:"p2p_transport"`
	CamouflageCertOrg         string                  `json:"camouflage_cert_org"`
	CamouflageCertCN          string                  `json:"camouflage_cert_cn"`
	C2Routes                  jsonC2Routing           `json:"c2_routes"`
	C2ChannelMode             string                  `json:"c2_channel_mode"`
	CCHTTPPort                string                  `json:"cc_http_port"`
	MalleableC2               jsonMalleableHTTPConfig `json:"malleable_c2"`
}

// applyIfSet copies src into *dst when src is non-zero, preserving a default the
// caller already seeded. JSON decoding leaves absent fields at their zero value;
// this merge rule is what lets readJSONConfig lay a partial document over an
// existing config without wiping it.
func applyIfSet[T comparable](dst *T, src T) {
	var zero T
	if src != zero {
		*dst = src
	}
}

// readJSONConfig parses a JSON config document and applies it to cfg. The
// document uses the snake_case schema defined by jsonConfig; unknown keys are
// ignored. Fields absent from the document keep the value already in cfg, so
// callers may seed defaults first. It also fills in the derived values the rest
// of the code expects (agent UUID, default C2 channel mode and idle timeout,
// normalized C2 routes, and the https:// CC address prefix).
func readJSONConfig(jsonData []byte, cfg *def.Config) error {
	var jCfg jsonConfig
	if err := json.Unmarshal(jsonData, &jCfg); err != nil {
		return fmt.Errorf("failed to parse JSON config: %w", err)
	}

	// Presence, not value, determines the operator idle timeout default: an
	// explicitly-written 0 disables idle rejection, while an absent key means
	// "use the 30 minute default".
	var present map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &present); err != nil {
		return fmt.Errorf("failed to parse JSON config: %w", err)
	}

	applyIfSet(&cfg.CCAddress, jCfg.CCAddress)
	applyIfSet(&cfg.CCHost, jCfg.CCHost)
	applyIfSet(&cfg.CCH2Port, jCfg.CCPort)
	applyIfSet(&cfg.AgentSocksServerPort, jCfg.AgentSocksServerPort)
	applyIfSet(&cfg.AgentSocksTimeout, jCfg.AgentSocksTimeout)
	applyIfSet(&cfg.StagerHTTPListenerPort, jCfg.StagerHTTPListenerPort)
	applyIfSet(&cfg.Password, jCfg.Password)
	applyIfSet(&cfg.ShadowsocksLocalSocksPort, jCfg.ShadowsocksLocalSocksPort)
	applyIfSet(&cfg.ShadowsocksServerPort, jCfg.ShadowsocksServerPort)
	applyIfSet(&cfg.P2PRelayPort, jCfg.KCPServerPort)
	applyIfSet(&cfg.KCPClientPort, jCfg.KCPClientPort)
	applyIfSet(&cfg.UseKCP, jCfg.UseKCP)
	applyIfSet(&cfg.EnableNCSI, jCfg.EnableNCSI)
	if jCfg.SSHHostKey != "" {
		cfg.SSHHostKey = []byte(jCfg.SSHHostKey)
	}
	applyIfSet(&cfg.SSHDShellPort, jCfg.SSHDShellPort)
	applyIfSet(&cfg.MeshGossipPort, jCfg.MeshGossipPort)
	applyIfSet(&cfg.PreflightEnabled, jCfg.PreflightEnabled)
	applyIfSet(&cfg.PreflightURL, jCfg.PreflightURL)
	applyIfSet(&cfg.PreflightMethod, jCfg.PreflightMethod)
	if len(jCfg.PreflightHeaders) > 0 {
		cfg.PreflightHeaders = jCfg.PreflightHeaders
	}
	applyIfSet(&cfg.PreflightIntervalMin, jCfg.PreflightIntervalMin)
	applyIfSet(&cfg.PreflightIntervalMax, jCfg.PreflightIntervalMax)
	applyIfSet(&cfg.CAPEM, jCfg.CAPEM)
	applyIfSet(&cfg.CAFingerprint, jCfg.CAFingerprint)
	applyIfSet(&cfg.C2TransportProxy, jCfg.C2TransportProxy)
	applyIfSet(&cfg.CDNProxy, jCfg.CDNProxy)
	applyIfSet(&cfg.DoHServer, jCfg.DoHServer)
	applyIfSet(&cfg.AgentUUID, jCfg.AgentUUID)
	applyIfSet(&cfg.AgentUUIDSig, jCfg.AgentUUIDSig)
	applyIfSet(&cfg.AgentTag, jCfg.AgentTag)
	applyIfSet(&cfg.CCTimeout, jCfg.CCTimeout)
	applyIfSet(&cfg.PaddingMin, jCfg.PaddingMin)
	applyIfSet(&cfg.PaddingMax, jCfg.PaddingMax)
	applyIfSet(&cfg.Jitter, jCfg.Jitter)
	applyIfSet(&cfg.PollInterval, jCfg.PollInterval)
	applyIfSet(&cfg.ModulePath, jCfg.ModulePath)
	applyIfSet(&cfg.IsRunByStager, jCfg.IsRunByStager)
	applyIfSet(&cfg.MachineID, jCfg.MachineID)
	if len(jCfg.InitialPeers) > 0 {
		cfg.InitialPeers = jCfg.InitialPeers
	}
	applyIfSet(&cfg.IsP2PEnabled, jCfg.IsP2PEnabled)
	applyIfSet(&cfg.IsDirectC2Enabled, jCfg.IsDirectC2Enabled)
	applyIfSet(&cfg.PersistentRouter, jCfg.PersistentRouter)
	applyIfSet(&cfg.P2PTransport, jCfg.P2PTransport)
	applyIfSet(&cfg.CamouflageCertOrg, jCfg.CamouflageCertOrg)
	applyIfSet(&cfg.CamouflageCertCN, jCfg.CamouflageCertCN)
	applyIfSet(&cfg.C2ChannelMode, jCfg.C2ChannelMode)
	applyIfSet(&cfg.CCHTTPPort, jCfg.CCHTTPPort)

	applyIfSet(&cfg.C2Routes.Checkin, jCfg.C2Routes.Checkin)
	applyIfSet(&cfg.C2Routes.Msg, jCfg.C2Routes.Msg)
	applyIfSet(&cfg.C2Routes.FTP, jCfg.C2Routes.FTP)
	applyIfSet(&cfg.C2Routes.WWW, jCfg.C2Routes.WWW)
	applyIfSet(&cfg.C2Routes.Proxy, jCfg.C2Routes.Proxy)

	applyIfSet(&cfg.MalleableC2.C2Path, jCfg.MalleableC2.C2Path)
	applyIfSet(&cfg.MalleableC2.SessionHeader, jCfg.MalleableC2.SessionHeader)
	applyIfSet(&cfg.MalleableC2.SessionValue, jCfg.MalleableC2.SessionValue)
	applyIfSet(&cfg.MalleableC2.InitHeader, jCfg.MalleableC2.InitHeader)
	applyIfSet(&cfg.MalleableC2.InitValue, jCfg.MalleableC2.InitValue)
	applyIfSet(&cfg.MalleableC2.CloseHeader, jCfg.MalleableC2.CloseHeader)
	applyIfSet(&cfg.MalleableC2.CloseValue, jCfg.MalleableC2.CloseValue)
	if len(jCfg.MalleableC2.CustomHeaders) > 0 {
		cfg.MalleableC2.CustomHeaders = jCfg.MalleableC2.CustomHeaders
	}

	// Derived defaults. These run last so a value from the document always wins.
	if _, ok := present["operator_idle_timeout"]; ok {
		cfg.OperatorIdleTimeout = jCfg.OperatorIdleTimeout
	} else {
		cfg.OperatorIdleTimeout = 1800
	}
	if cfg.AgentUUID == "" {
		cfg.AgentUUID = uuid.NewString()
	}
	if cfg.C2ChannelMode == "" {
		cfg.C2ChannelMode = def.C2ChannelModeDefault
	}
	def.NormalizeC2Routes(&cfg.C2Routes)

	// The stored address is host-only; the transport layer expects a URL.
	def.CCAddress = fmt.Sprintf("https://%s", cfg.CCAddress)

	return nil
}
