package operator

import (
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

var (
	// OperatorHTTPClient is an HTTP/2 client for the mTLS C2 operator server
	OperatorHTTPClient *http.Client

	// OperatorRootURL is the root URL of the mTLS C2 operator server
	OperatorRootURL string
)

// createMTLSHttpClient connects to the mTLS server and returns an HTTP/2 client
func createMTLSHttpClient() (*http.Client, error) {
	// Call controller for business logic
	cfg := controllers.MTLSClientConfig{
		ClientCertFile: transport.OperatorClientCrtFile,
		ClientKeyFile:  transport.OperatorClientKeyFile,
		CACertFile:     transport.OperatorCaCrtFile,
		Timeout:        30 * time.Second,
	}
	return controllers.CreateMTLSClient(cfg)
}
