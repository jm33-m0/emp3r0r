//go:build !with_quic

package server

import "errors"

// StartC2QUICServer is the stub used when the build excludes the QUIC
// transport. It reports the missing feature to the caller and returns; other
// transports (h2conn, http_poll, raw TLS) are unaffected.
func StartC2QUICServer() error {
	return errors.New("QUIC C2 transport is not compiled into this build")
}
