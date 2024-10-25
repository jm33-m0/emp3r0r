//go:build linux
// +build linux

package cc

import (
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// KCPListenAndServe KCP server for Shadowsocks
func KCPListenAndServe() {
	tun.KCPTunServer("127.0.0.1:"+RuntimeConfig.ShadowsocksPort,
		RuntimeConfig.KCPPort, RuntimeConfig.Password, emp3r0r_data.MagicString)
}
