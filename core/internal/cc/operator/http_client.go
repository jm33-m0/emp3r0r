package operator

import (
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
)

// createOperatorHTTPClient returns the HTTP client the operator console uses to
// reach the C2 operator service over the userspace WireGuard tunnel.
func createOperatorHTTPClient() *http.Client {
	return controllers.CreateOperatorHTTPClient(wireguard.DialContext)
}
