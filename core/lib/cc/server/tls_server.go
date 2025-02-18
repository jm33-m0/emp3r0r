package server

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// StartTLSServer starts the TLS server.
func StartTLSServer() {
	if _, err := os.Stat(def.Temp + tun.WWW); os.IsNotExist(err) {
		err = os.MkdirAll(def.Temp+tun.WWW, 0o700)
		if err != nil {
			logging.Fatalf("StartTLSServer: %v", err)
		}
	}
	r := mux.NewRouter()
	tun.CACrtPEM = []byte(def.RuntimeConfig.CAPEM)
	r.HandleFunc(fmt.Sprintf("/%s/{api}/{token}", tun.WebRoot), apiDispatcher)
	if EmpTLSServer != nil {
		EmpTLSServer.Shutdown(EmpTLSServerCtx)
	}
	EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", def.RuntimeConfig.CCPort),
		Handler: r,
	}
	EmpTLSServerCtx, EmpTLSServerCancel = context.WithCancel(context.Background())
	logging.Debugf("Starting C2 TLS service at port %s", def.RuntimeConfig.CCPort)
	err := EmpTLSServer.ListenAndServeTLS(def.ServerCrtFile, def.ServerKeyFile)
	if err != nil {
		if err == http.ErrServerClosed {
			logging.Warningf("C2 TLS service is shutdown")
			return
		}
		logging.Fatalf("Failed to start HTTPS server at *:%s: %v", def.RuntimeConfig.CCPort, err)
	}
}
