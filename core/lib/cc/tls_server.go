package cc

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// StartTLSServer starts the TLS server.
func StartTLSServer() {
	if _, err := os.Stat(Temp + tun.WWW); os.IsNotExist(err) {
		err = os.MkdirAll(Temp+tun.WWW, 0o700)
		if err != nil {
			LogFatal("StartTLSServer: %v", err)
		}
	}
	r := mux.NewRouter()
	tun.CACrtPEM = []byte(RuntimeConfig.CAPEM)
	r.HandleFunc(fmt.Sprintf("/%s/{api}/{token}", tun.WebRoot), apiDispatcher)
	if EmpTLSServer != nil {
		EmpTLSServer.Shutdown(EmpTLSServerCtx)
	}
	EmpTLSServer = &http.Server{
		Addr:    fmt.Sprintf(":%s", RuntimeConfig.CCPort),
		Handler: r,
	}
	EmpTLSServerCtx, EmpTLSServerCancel = context.WithCancel(context.Background())
	LogDebug("Starting C2 TLS service at port %s", RuntimeConfig.CCPort)
	err := EmpTLSServer.ListenAndServeTLS(ServerCrtFile, ServerKeyFile)
	if err != nil {
		if err == http.ErrServerClosed {
			LogWarning("C2 TLS service is shutdown")
			return
		}
		LogFatal("Failed to start HTTPS server at *:%s: %v", RuntimeConfig.CCPort, err)
	}
}
