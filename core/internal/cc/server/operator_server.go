package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartOperatorServer starts the operator HTTP service on the userspace
// WireGuard stack. WireGuard authenticates and encrypts the peer and
// cryptokey-routes its tunnel address, so handlers derive operator identity
// from the source address. The listener is unreachable off-tunnel, so it needs
// no TLS of its own.
func StartOperatorServer(port int) {
	r := mux.NewRouter()
	r.HandleFunc(fmt.Sprintf("/%s/{api}", transport.OperatorRoot), operationDispatcher)
	if network.OperatorServer != nil && network.OperatorServerCtx != nil {
		network.OperatorServer.Shutdown(network.OperatorServerCtx)
	}

	network.OperatorServer = &http.Server{
		Handler: r,
	}
	network.OperatorServerCtx, network.OperatorServerCancel = context.WithCancel(context.Background())
	logging.Successf("🚀 Starting C2 operator service (HTTP over WireGuard) at port %d", port)

	listenAddr := fmt.Sprintf("%s:%d", wireguard.WgServerIP, port)
	ln, err := wireguard.Listen("tcp", listenAddr)
	if err != nil {
		logging.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	err = network.OperatorServer.Serve(ln)
	if err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 operator service is shutdown")
			return
		}
		logging.Fatalf("Failed to start operator HTTP server at %s: %v", listenAddr, err)
	}
}
