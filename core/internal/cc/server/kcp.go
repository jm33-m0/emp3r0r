package server

import (
	"context"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

// KCPC2ListenAndServe KCP server that forwards to C2 port
func KCPC2ListenAndServe() {
	ctx, cancel := context.WithCancel(context.Background())
	tun.KCPTunServer("127.0.0.1:"+runtime_def.RuntimeConfig.CCPort,
		runtime_def.RuntimeConfig.KCPServerPort, runtime_def.RuntimeConfig.Password, emp3r0r_def.MagicString, ctx, cancel)
}
