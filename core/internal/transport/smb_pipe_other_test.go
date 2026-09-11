//go:build !windows

package transport

import (
	"errors"
	"testing"
)

func TestSMBTransportUnsupportedOnNonWindows(t *testing.T) {
	srv := SMBTransport{}
	if srv.Supported() {
		t.Fatal("SMBTransport.Supported() = true on a non-Windows platform")
	}
	if _, err := srv.Listen("44444", "pw", "salt"); !errors.Is(err, ErrSMBNotSupported) {
		t.Fatalf("Listen error = %v, want ErrSMBNotSupported", err)
	}
	if _, err := srv.Dial("192.0.2.1:44444", "pw", "salt"); !errors.Is(err, ErrSMBNotSupported) {
		t.Fatalf("Dial error = %v, want ErrSMBNotSupported", err)
	}
}

// TestPeerTransportSelectionRejectsSMB asserts that a non-Windows node will not
// try to dial a peer that only listens on SMB, so gateway/file-source selection
// skips it instead of dialling a wrong listener.
func TestPeerTransportSelectionRejectsSMB(t *testing.T) {
	if PeerDialable("smb", "mtls") {
		t.Fatal("PeerDialable(smb) = true on a non-Windows platform")
	}
	if _, _, err := ResolvePeerTransport("smb", "mtls"); err == nil {
		t.Fatal("ResolvePeerTransport(smb) should fail on a non-Windows platform")
	}
	// A peer that advertised nothing still falls back to the local default.
	if !PeerDialable("", "mtls") {
		t.Fatal("PeerDialable(\"\", mtls) = false, want true")
	}
}
