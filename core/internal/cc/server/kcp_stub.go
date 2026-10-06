//go:build no_kcp

package server

import "context"

// KCPC2ListenAndServe is the no-op stub used when the build excludes the KCP
// transport. The C2 does not listen for KCP agents in that configuration.
func KCPC2ListenAndServe(ctx context.Context, cancel context.CancelFunc) {
	_ = ctx
	_ = cancel
}
