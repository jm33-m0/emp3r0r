//go:build !with_quic

package transport

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestQUICChannelAbsentWithoutTag pins the opt-in contract: without the
// with_quic tag the channel is not registered, so callers get a clear error
// instead of a half-compiled transport. The with_quic build asserts the
// opposite in TestQUICChannelWrapperRegistered.
func TestQUICChannelAbsentWithoutTag(t *testing.T) {
	if _, err := GetC2ChannelWrapper(def.C2ChannelModeQUIC); err == nil {
		t.Fatal("quic channel registered without the with_quic tag")
	}
}
