//go:build no_h2conn

package server

import "github.com/jm33-m0/emp3r0r/core/lib/logging"

// StartC2H2StreamServer is the stub used when the build excludes the h2conn
// channel. The plain HTTP poll server is started independently, so a C2 built
// without h2conn still serves http_poll agents.
func StartC2H2StreamServer() {
	logging.Warningf("C2 h2 stream server is not compiled into this build")
}
