package controllers

import (
	"context"
	"net"
	"net/http"
)

// CreateOperatorHTTPClient creates the plain HTTP client the operator uses to
// reach the C2 operator service. The service lives on the userspace WireGuard
// stack, which authenticates and encrypts the peer, so the client only needs to
// route its TCP dial through that stack.
func CreateOperatorHTTPClient(dialContext func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: dialContext,
		},
		// No global timeout: the message tunnel is a long-lived stream and
		// per-request contexts carry their own deadlines.
	}
}
