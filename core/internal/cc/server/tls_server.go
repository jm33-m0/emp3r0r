package server

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

// StartTLSServer starts the TLS server.
func StartTLSServer() {
	if _, err := os.Stat(runtime_def.Temp + tun.WWW); os.IsNotExist(err) {
		err = os.MkdirAll(runtime_def.Temp+tun.WWW, 0o700)
		if err != nil {
			logging.Fatalf("StartTLSServer: %v", err)
		}
	}
	r := mux.NewRouter()
	tun.CACrtPEM = []byte(runtime_def.RuntimeConfig.CAPEM)
	r.HandleFunc(fmt.Sprintf("/%s/{api}/{token}", tun.WebRoot), apiDispatcher)
	if network.EmpTLSServer != nil {
		network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
	}
	network.EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", runtime_def.RuntimeConfig.CCPort),
		Handler: r,
	}
	network.EmpTLSServerCtx, network.EmpTLSServerCancel = context.WithCancel(context.Background())
	logging.Debugf("Starting C2 TLS service at port %s", runtime_def.RuntimeConfig.CCPort)
	err := network.EmpTLSServer.ListenAndServeTLS(runtime_def.ServerCrtFile, runtime_def.ServerKeyFile)
	if err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 TLS service is shutdown")
			return
		}
		logging.Fatalf("Failed to start HTTPS server at *:%s: %v", runtime_def.RuntimeConfig.CCPort, err)
	}
}
