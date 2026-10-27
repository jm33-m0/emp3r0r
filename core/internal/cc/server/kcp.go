//go:build with_kcp

package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// KCPC2ListenAndServe KCP server that forwards to C2 port. It blocks until the
// context is cancelled and returns the server error, so the caller can report
// it without tearing down the C2.
func KCPC2ListenAndServe(ctx context.Context, cancel context.CancelFunc) error {
	logging.Successf("🚀 Starting KCP C2 server at port %s", live.GetRuntimeConfig().P2PRelayPort)
	return transport.KCPTunServer("127.0.0.1:"+live.GetRuntimeConfig().CCH2Port,
		live.GetRuntimeConfig().P2PRelayPort, live.GetRuntimeConfig().Password, def.MagicString, ctx, cancel)
}
