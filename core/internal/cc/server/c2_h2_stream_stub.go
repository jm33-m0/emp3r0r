//go:build !with_h2conn

package server

import "errors"

// StartC2H2StreamServer is the stub used when the build excludes the h2conn
// channel. It reports the missing feature to the caller and returns; the plain
// HTTP poll server is started independently, so a C2 built without h2conn still
// serves http_poll agents.
func StartC2H2StreamServer() error {
	return errors.New("h2conn C2 channel is not compiled into this build")
}
