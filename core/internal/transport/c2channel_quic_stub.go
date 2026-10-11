//go:build !with_quic

package transport

// This build excludes the QUIC transport. The stubs keep the rest of the
// transport package compiling when callers configure the (absent) transport.

// SetQUICStandardKey is a no-op when the QUIC transport is not compiled in.
func SetQUICStandardKey(bool) {}
