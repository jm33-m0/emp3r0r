package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartOperatorMTLSServer starts the operator TLS server with mTLS.
func StartOperatorMTLSServer(port int) {
	r := mux.NewRouter()
	r.HandleFunc(fmt.Sprintf("/%s/{api}", transport.OperatorRoot), operationDispatcher)
	if network.MTLSServer != nil && network.MTLSServerCtx != nil {
		network.MTLSServer.Shutdown(network.MTLSServerCtx)
	}

	// Load client CA certificate
	clientCACert, err := os.ReadFile(transport.OperatorCaCrtFile)
	if err != nil {
		logging.Fatalf("Failed to read client CA certificate: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCACert) {
		logging.Fatalf("Failed to append client CA certificate")
	}

	// Configure TLS with mTLS
	tlsConfig := &tls.Config{
		ClientCAs:  clientCAs,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	network.MTLSServer = &http.Server{
		Addr:      fmt.Sprintf("%s:%d", wireguard.WgServerIP, port),
		Handler:   r,
		TLSConfig: tlsConfig,
	}
	network.MTLSServerCtx, network.MTLSServerCancel = context.WithCancel(context.Background())
	logging.Successf("🚀 Starting C2 operator service with mTLS at port %d", port)
	err = network.MTLSServer.ListenAndServeTLS(transport.OperatorServerCrtFile, transport.OperatorServerKeyFile)
	if err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 operator service is shutdown")
			return
		}
		logging.Fatalf("Failed to start HTTPS (mTLS) server at *:%d: %v", port, err)
	}
}
