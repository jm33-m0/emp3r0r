//go:build no_quic

package server

import "github.com/jm33-m0/emp3r0r/core/lib/logging"

// StartC2QUICServer is the stub used when the build excludes the QUIC
// transport. Other transports (h2conn, http_poll, raw TLS) are unaffected.
func StartC2QUICServer() {
	logging.Warningf("C2 QUIC listener is not compiled into this build")
}
