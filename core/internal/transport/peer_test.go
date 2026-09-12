package transport

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestPeerEndpointNetworkAddr(t *testing.T) {
	cases := []struct {
		name         string
		ep           PeerEndpoint
		fallbackPort int
		want         string
	}{
		{"bare ip with advertised port", PeerEndpoint{Addr: "10.0.0.1", Port: 4000}, 9999, "10.0.0.1:4000"},
		{"bare ip uses fallback port", PeerEndpoint{Addr: "10.0.0.1"}, 4000, "10.0.0.1:4000"},
		{"existing host:port respected", PeerEndpoint{Addr: "10.0.0.1:1234", Port: 4000}, 9999, "10.0.0.1:1234"},
		{"no port anywhere", PeerEndpoint{Addr: "10.0.0.1"}, 0, "10.0.0.1"},
		{"empty address", PeerEndpoint{}, 4000, ""},
		{"ipv6 bare gets bracketed", PeerEndpoint{Addr: "fe80::1", Port: 4000}, 0, "[fe80::1]:4000"},
		{"ipv6 existing hostport", PeerEndpoint{Addr: "[fe80::1]:4000"}, 0, "[fe80::1]:4000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ep.NetworkAddr(tc.fallbackPort); got != tc.want {
				t.Errorf("NetworkAddr() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolvePeerTransport(t *testing.T) {
	cases := []struct {
		name          string
		peerTransport string
		fallback      string
		wantName      string
		wantErr       bool
	}{
		{"peer advertised transport wins", "kcp", "mtls", "kcp", false},
		{"peer matches fallback", "mtls", "mtls", "mtls", false},
		{"empty peer uses fallback", "", "kcp", "kcp", false},
		{"nothing configured defaults to mtls", "", "", "mtls", false},
		{"unknown peer transport is an error", "quic", "mtls", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, name, err := ResolvePeerTransport(tc.peerTransport, tc.fallback)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got transport %q", name)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolvePeerTransport: %v", err)
			}
			if got == nil {
				t.Fatal("resolved transport is nil")
			}
			if name != tc.wantName {
				t.Fatalf("resolved name = %q, want %q", name, tc.wantName)
			}
			if !PeerDialable(tc.peerTransport, tc.fallback) {
				t.Fatalf("PeerDialable(%q, %q) = false, want true", tc.peerTransport, tc.fallback)
			}
			want, werr := GetTransportImplementationStrict(tc.wantName)
			if werr != nil {
				t.Fatalf("strict lookup of %q: %v", tc.wantName, werr)
			}
			if got != want {
				t.Fatalf("resolved transport does not match registry entry %q", tc.wantName)
			}
		})
	}

	if PeerDialable("quic", "mtls") {
		t.Error("PeerDialable(quic) = true, want false")
	}
}

func TestResolvePeerTransportNeverSubstitutes(t *testing.T) {
	// A peer that advertised an unknown transport must not silently fall back
	// to the local default: that would dial a listener the peer is not running.
	_, name, err := ResolvePeerTransport("does-not-exist", "mtls")
	if err == nil {
		t.Fatalf("expected error, resolved %q instead", name)
	}
	if name != "" {
		t.Fatalf("resolved name = %q on error, want empty", name)
	}
}

func TestGetTransportImplementationStrict(t *testing.T) {
	if _, err := GetTransportImplementationStrict("mtls"); err != nil {
		t.Fatalf("strict lookup of mtls: %v", err)
	}
	// Unknown names must fail rather than silently resolving to some default.
	if _, err := GetTransportImplementationStrict("nope"); err == nil {
		t.Fatal("strict lookup of unknown transport should fail")
	}
}

func TestUsableTransportRejectsUnsupported(t *testing.T) {
	if _, err := UsableTransport("nope"); err == nil {
		t.Fatal("UsableTransport(unknown) should fail")
	}
	if _, err := UsableTransport("mtls"); err != nil {
		t.Fatalf("UsableTransport(mtls): %v", err)
	}
}

func TestDialPeerFailsBeforeNetworkForBadTransport(t *testing.T) {
	// An unresolvable transport must fail without attempting a connection, so
	// callers can cheaply skip incompatible peers in a mixed mesh.
	_, err := DialPeer(PeerEndpoint{Addr: "127.0.0.1", Port: 1, Transport: "quic"}, "mtls", 1, "pw", "salt")
	if err == nil {
		t.Fatal("DialPeer with unknown transport should fail")
	}
	if !strings.Contains(err.Error(), "quic") {
		t.Fatalf("error should name the offending transport, got: %v", err)
	}

	// An empty address must also fail cleanly.
	if _, err := DialPeer(PeerEndpoint{Transport: "mtls"}, "mtls", 0, "pw", "salt"); err == nil {
		t.Fatal("DialPeer with empty address should fail")
	}
}

// TestTransportCapabilities asserts every registered transport reports a
// capability and that the mesh supports the transports the project relies on.
func TestTransportCapabilities(t *testing.T) {
	for _, name := range AllTransportNames() {
		tr, err := GetTransportImplementationStrict(name)
		if err != nil {
			t.Fatalf("registered transport %q not strictly resolvable: %v", name, err)
		}
		_ = tr.Supported() // must not panic
	}
	for _, want := range []string{"kcp", "mtls", "smb"} {
		if _, err := GetTransportImplementationStrict(want); err != nil {
			t.Errorf("expected transport %q to be registered: %v", want, err)
		}
	}
	// mTLS is the documented fallback and must always be usable.
	mtls, err := GetTransportImplementationStrict(DefaultMeshTransport)
	if err != nil {
		t.Fatalf("default transport %q not registered: %v", DefaultMeshTransport, err)
	}
	if !mtls.Supported() {
		t.Error("mtls must be supported on every platform")
	}
}

// TestTransportUsesNetworkPort guards the operator-facing distinction between
// transports that open a dialable port and SMB, whose relay "port" only derives
// the pipe name.
func TestTransportUsesNetworkPort(t *testing.T) {
	for _, name := range []string{"kcp", "mtls"} {
		if !TransportUsesNetworkPort(name) {
			t.Errorf("%s should report using a network port", name)
		}
	}
	if TransportUsesNetworkPort(smbTransportName) {
		t.Errorf("%s should report no network port", smbTransportName)
	}
	// Unknown transports default to "uses a port", the safe default for messaging.
	if !TransportUsesNetworkPort("does-not-exist") {
		t.Error("unknown transport should default to using a network port")
	}
}

// TestPeerDialContextContract guards that the dial path keeps using the
// transport's own Dial signature; it is the seam agent code relies on.
func TestPeerDialContextContract(t *testing.T) {
	mock := &mockTransport{}
	Transports.Store("__mock__", &TransportDescriptor{Name: "__mock__", Transport: mock})
	t.Cleanup(func() { Transports.Delete("__mock__") })

	conn, err := DialPeer(PeerEndpoint{Addr: "peer", Port: 1, Transport: "__mock__"}, "mtls", 0, "pw", "salt")
	if err != nil {
		t.Fatalf("DialPeer via mock: %v", err)
	}
	conn.Close()
	if mock.dialAddr != "peer:1" {
		t.Fatalf("mock saw addr %q, want peer:1", mock.dialAddr)
	}
	if mock.dialPass != "pw" || mock.dialSalt != "salt" {
		t.Fatalf("mock saw (%q,%q), want (pw,salt)", mock.dialPass, mock.dialSalt)
	}
}

type mockTransport struct {
	dialAddr string
	dialPass string
	dialSalt string
}

func (m *mockTransport) Dial(addr, password, salt string) (net.Conn, error) {
	m.dialAddr, m.dialPass, m.dialSalt = addr, password, salt
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

func (m *mockTransport) Listen(port, password, salt string) (net.Listener, error) {
	return nil, nil
}

func (m *mockTransport) Accept(ctx context.Context, l net.Listener) (net.Conn, error) {
	return nil, nil
}

func (m *mockTransport) Supported() bool { return true }
