//go:build with_transport_tor

package main

// Compile the Tor example dialer only when the operator asks for it:
//
//	build.py --agent-tags "with_transport_tor ..."
import _ "github.com/jm33-m0/emp3r0r/core/examples/transports/tor"
