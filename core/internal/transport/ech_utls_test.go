//go:build with_utls && with_doh && with_ech

package transport

import (
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestECHHandshakeRealDomainUTLS drives the agent's uTLS ECH path against real
// ECH-publishing domains and asserts the server accepted ECH. This is the test
// that caught the randomized preset producing a malformed outer ClientHello:
// ECH only works with the browser parrots, so c2ClientHelloID must return one
// when ECH is enabled.
func TestECHHandshakeRealDomainUTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("real-network integration test")
	}
	// ECH is disabled at this point, so the randomized preset must be selected.
	SetECHConfig("", "")
	if id := c2ClientHelloID(); id != clientHelloIDMap["hellorandomizedalpn"] {
		t.Fatalf("c2ClientHelloID without ECH = %v, want the randomized preset", id)
	}
	for _, domain := range echRealDomains {
		t.Run(domain, func(t *testing.T) {
			SetECHConfig(domain, echRealDoH)
			defer SetECHConfig("", "")

			if id := c2ClientHelloID(); id != clientHelloIDMap["hellochrome_auto"] {
				t.Fatalf("c2ClientHelloID with ECH = %v, want the Chrome parametric preset", id)
			}
			conn, err := dialUTLSWithECH("tcp", domain+":443", &utls.Config{ServerName: domain}, c2ClientHelloID(), &net.Dialer{Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("uTLS ECH handshake with %s: %v", domain, err)
			}
			defer conn.Close()
			state := conn.ConnectionState()
			if !state.ECHAccepted {
				t.Fatalf("%s did not accept ECH (ALPN %q)", domain, state.NegotiatedProtocol)
			}
			if state.NegotiatedProtocol == "" {
				t.Fatalf("%s negotiated no ALPN", domain)
			}
		})
	}
}
