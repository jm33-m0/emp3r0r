package agentutils

import (
	"fmt"
	"net/url"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

// set C2Transport string
func genC2TransportString() (transport_str string) {
	if netutil.IsTor(def.CCAddress) {
		return fmt.Sprintf("TOR (%s)", def.CCAddress)
	} else if common.RuntimeConfig.CDNProxy != "" {
		return fmt.Sprintf("CDN (%s)", common.RuntimeConfig.CDNProxy)
	} else if common.RuntimeConfig.UseKCP {
		return fmt.Sprintf("KCP (%s)",
			def.CCAddress)
	} else if common.RuntimeConfig.C2TransportProxy != "" {
		// parse proxy url
		proxyURL, err := url.Parse(common.RuntimeConfig.C2TransportProxy)
		if err != nil {
			logging.Infof("invalid proxy URL: %v", err)
		}

		// if the proxy port is the proxy server's port
		if proxyURL.Port() == common.RuntimeConfig.AgentSocksServerPort && proxyURL.Hostname() == "127.0.0.1" {
			return fmt.Sprintf("Reverse Proxy: %s", common.RuntimeConfig.C2TransportProxy)
		}
		if proxyURL.Port() == common.RuntimeConfig.ShadowsocksLocalSocksPort && proxyURL.Hostname() == "127.0.0.1" {
			return fmt.Sprintf("Auto Proxy: %s", common.RuntimeConfig.C2TransportProxy)
		}

		return fmt.Sprintf("Proxy %s", common.RuntimeConfig.C2TransportProxy)
	} else {
		return fmt.Sprintf("HTTP2 (%s)", def.CCAddress)
	}
}
