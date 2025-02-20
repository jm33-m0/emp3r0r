package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// KCPC2ListenAndServe KCP server that forwards to C2 port
func KCPC2ListenAndServe() {
	ctx, cancel := context.WithCancel(context.Background())
	transport.KCPTunServer("127.0.0.1:"+live.RuntimeConfig.CCPort,
		live.RuntimeConfig.KCPServerPort, live.RuntimeConfig.Password, def.MagicString, ctx, cancel)
}
