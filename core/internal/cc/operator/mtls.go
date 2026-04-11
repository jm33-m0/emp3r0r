package operator

import (
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// createMTLSHttpClient connects to the mTLS server and returns an HTTP/2 client
func createMTLSHttpClient() (*http.Client, error) {
	// Call controller for business logic
	cfg := controllers.MTLSClientConfig{
		ClientCertFile: transport.OperatorClientCrtFile,
		ClientKeyFile:  transport.OperatorClientKeyFile,
		CACertFile:     transport.OperatorCaCrtFile,
		// Keep client-wide timeout disabled for long-lived h2 message tunnel streams.
		// Request-level deadlines are enforced by per-request contexts.
		Timeout: -1 * time.Second,
	}
	return controllers.CreateMTLSClient(cfg)
}
