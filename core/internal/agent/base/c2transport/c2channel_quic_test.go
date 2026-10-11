//go:build !no_quic

package c2transport_test

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// TestQUICCheckinACK drives the full agent -> C2 check-in over the real QUIC
// channel: StartC2AgentTLSServer starts the QUIC listener, EstablishC2Connection
// dials it through the registered wrapper, and the MsgAuth/CBOR dispatcher
// registers the agent. Both the default custom-key obfuscation and the
// standard-key opt-out are exercised.
func TestQUICCheckinACK(t *testing.T) {
	if _, err := transport.GetC2ChannelWrapper(def.C2ChannelModeQUIC); err != nil {
		t.Skipf("quic channel not compiled into this build: %v", err)
	}
	for _, tc := range []struct {
		name     string
		standard bool
	}{
		{"custom-key", false},
		{"standard-key", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runCheckinACK(t, def.C2ChannelModeQUIC, tc.standard)
		})
	}
}
