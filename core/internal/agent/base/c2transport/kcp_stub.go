//go:build no_kcp

package c2transport

import "github.com/jm33-m0/emp3r0r/core/lib/logging"

// RunKCPClient is the no-op stub used when the build excludes the KCP C2
// transport, so cmd/agent compiles without the xtaci stack.
func RunKCPClient() {
	logging.Warningf("KCP transport is not compiled into this agent")
}
