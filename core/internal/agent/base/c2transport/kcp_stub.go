//go:build !with_kcp

package c2transport

import "errors"

// RunKCPClient is the stub used when the build excludes the KCP C2 transport.
// It reports the missing feature so cmd/agent can log it and keep running,
// rather than silently dropping the configured KCP tunnel.
func RunKCPClient() error {
	return errors.New("KCP transport is not compiled into this agent")
}
