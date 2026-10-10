package network

import (
	"context"
	"net/http"
)

// OperatorServer is the operator-facing HTTP server. It is bound to the
// userspace WireGuard stack, so the peer address is the operator's provisioned
// WireGuard IP and WireGuard already authenticates and encrypts the channel;
// no application-layer TLS is layered on top.
var (
	OperatorServer       *http.Server
	OperatorServerCtx    context.Context
	OperatorServerCancel context.CancelFunc
)
