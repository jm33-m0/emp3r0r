//go:build !with_kcp

package server

import (
	"context"
	"errors"
)

// KCPC2ListenAndServe is the stub used when the build excludes the KCP
// transport. It reports the missing feature and returns immediately; the C2
// keeps serving its other transports.
func KCPC2ListenAndServe(ctx context.Context, cancel context.CancelFunc) error {
	_ = ctx
	_ = cancel
	return errors.New("KCP C2 transport is not compiled into this build")
}
