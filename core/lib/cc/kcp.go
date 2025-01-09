//go:build linux
// +build linux

package cc

import (
	"context"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// KCPSSListenAndServe KCP server for Shadowsocks
func KCPSSListenAndServe() {
	ctx, cancel := context.WithCancel(context.Background())
	tun.KCPTunServer("127.0.0.1:"+RuntimeConfig.ShadowsocksServerPort,
		RuntimeConfig.KCPServerPort, RuntimeConfig.Password, emp3r0r_data.MagicString, ctx, cancel)
}
