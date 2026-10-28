//go:build !linux

package server

import "net"

// checkBridgePeer is a no-op outside Linux. The C2 server is Linux-only; this
// stub keeps the package buildable on other platforms for tooling and tests.
func checkBridgePeer(net.Conn) error { return nil }
