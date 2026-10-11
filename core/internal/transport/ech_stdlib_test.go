//go:build !with_utls && with_doh && with_ech

package transport

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestECHHandshakeRealDomainStdlib drives the crypto/tls ECH path (the
// no-with_utls build) against real ECH-publishing domains and asserts the server
// accepted ECH and negotiated h2.
func TestECHHandshakeRealDomainStdlib(t *testing.T) {
	if testing.Short() {
		t.Skip("real-network integration test")
	}
	for _, domain := range echRealDomains {
		t.Run(domain, func(t *testing.T) {
			SetECHConfig(domain, echRealDoH)
			defer SetECHConfig("", "")

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			dial := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
			conn, err := dialStdTLSWithECH(ctx, "tcp", domain+":443", stdlibTLSConfig(domain, nil), dial)
			if err != nil {
				t.Fatalf("stdlib ECH handshake with %s: %v", domain, err)
			}
			defer conn.Close()
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				t.Fatalf("returned conn is %T, want *tls.Conn", conn)
			}
			state := tlsConn.ConnectionState()
			if !state.ECHAccepted {
				t.Fatalf("%s did not accept ECH (ALPN %q)", domain, state.NegotiatedProtocol)
			}
			if state.NegotiatedProtocol == "" {
				t.Fatalf("%s negotiated no ALPN", domain)
			}
		})
	}
}
