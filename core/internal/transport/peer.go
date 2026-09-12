package transport

// peer.go — transport-aware peer addressing and selection.
//
// A mesh is not guaranteed to be transport-homogeneous: a Windows agent may
// only listen on SMB named pipes while a Linux agent listens on mTLS or KCP.
// Each node therefore advertises the transport its relay listens on (see
// def.MeshNodeMeta.P2PTransport), and a dialer must use *that* transport for
// that peer instead of assuming everyone runs the local default.
//
// Selection rules:
//   - A peer that advertised a transport must be reached with it. Substituting
//     another transport would dial a listener the peer is not running, so an
//     unsupported peer transport is a hard error (the caller skips the peer).
//   - A peer that advertised nothing (e.g. it has not gossiped metadata yet)
//     is dialled with the local default transport, which preserves the
//     pre-transport-aware behaviour for that case.

import (
	"fmt"
	"net"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// DefaultMeshTransport is the transport assumed when neither the peer nor the
// local config names one. It preserves the historical mTLS default for nodes
// that predate transport advertisement, and is the single source of truth for
// that fallback.
const DefaultMeshTransport = "mtls"

// PeerEndpoint identifies how to reach a peer agent's mesh relay.
type PeerEndpoint struct {
	Addr      string // bare host/IP; an existing "host:port" is respected as-is
	Port      int    // peer's advertised P2P relay port; <=0 means unknown
	Transport string // peer's advertised transport; "" means unknown
}

// NetworkAddr renders the endpoint as a dialable "host:port", substituting
// fallbackPort when the peer did not advertise one. An Addr that already
// carries a port is returned unchanged, so callers may pass either form.
func (e PeerEndpoint) NetworkAddr(fallbackPort int) string {
	if e.Addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(e.Addr); err == nil {
		return e.Addr
	}
	port := e.Port
	if port <= 0 {
		port = fallbackPort
	}
	if port <= 0 {
		return e.Addr
	}
	return net.JoinHostPort(e.Addr, strconv.Itoa(port))
}

// GetTransportImplementationStrict returns the registered transport for name
// without the implicit mTLS fallback of GetTransportImplementation. Selection
// code must use this: silently dialling mTLS for a peer that advertised SMB
// would hit a listener the peer is not running.
func GetTransportImplementationStrict(name string) (MeshTransport, error) {
	val, ok := Transports.Load(name)
	if !ok {
		return nil, fmt.Errorf("unknown mesh transport %q", name)
	}
	td, ok := val.(*TransportDescriptor)
	if !ok || td == nil || td.Transport == nil {
		return nil, fmt.Errorf("invalid mesh transport descriptor %q", name)
	}
	return td.Transport, nil
}

// UsableTransport resolves name for a listen/dial operation, requiring that the
// platform actually supports it.
func UsableTransport(name string) (MeshTransport, error) {
	t, err := GetTransportImplementationStrict(name)
	if err != nil {
		return nil, err
	}
	if !t.Supported() {
		return nil, fmt.Errorf("mesh transport %q is not supported on this platform", name)
	}
	return t, nil
}

// PlatformTransport is implemented by transports that only run on a subset of
// GOOS values (e.g. SMB named pipes are Windows-only).
type PlatformTransport interface {
	SupportedOn(goos string) bool
}

// PortlessTransport is implemented by transports that do not open a network
// port, so the configured relay port only acts as an identifier (SMB derives its
// pipe name from it). Operator-facing output uses this to avoid describing a
// non-existent port as something peers can dial.
type PortlessTransport interface {
	Portless() bool
}

// TransportUsesNetworkPort reports whether the named transport opens a network
// port for peers to dial. Unknown transports are assumed to use one, which is
// the safe default for operator messaging.
func TransportUsesNetworkPort(name string) bool {
	t, err := GetTransportImplementationStrict(name)
	if err != nil {
		return true
	}
	if p, ok := t.(PortlessTransport); ok {
		return !p.Portless()
	}
	return true
}

// TransportSupportedOn reports whether the named transport can run on the given
// GOOS. The operator uses this at generation time to reject payload/transport
// combinations that could never work, since the runtime Supported() check
// reflects the build host rather than the payload's target OS.
func TransportSupportedOn(name, goos string) bool {
	t, err := GetTransportImplementationStrict(name)
	if err != nil {
		return false
	}
	if pt, ok := t.(PlatformTransport); ok {
		return pt.SupportedOn(goos)
	}
	return true
}

// ResolvePeerTransport picks the transport to reach a peer with. peerTransport
// is what the peer advertised in gossip; fallback is this node's configured
// transport, used only when the peer advertised none. It returns the transport
// and the resolved name for logging.
func ResolvePeerTransport(peerTransport, fallback string) (MeshTransport, string, error) {
	name := peerTransport
	if name == "" {
		name = fallback
	}
	if name == "" {
		name = DefaultMeshTransport
	}
	t, err := UsableTransport(name)
	if err != nil {
		return nil, "", err
	}
	return t, name, nil
}

// PeerDialable reports whether this node can dial a peer running peerTransport,
// failing over to fallback when the peer advertised none.
func PeerDialable(peerTransport, fallback string) bool {
	_, _, err := ResolvePeerTransport(peerTransport, fallback)
	return err == nil
}

// DialPeer dials a peer's relay using the transport the peer advertised,
// falling back to fallbackTransport/fallbackPort only when the peer did not
// advertise them. The returned connection is already wrapped in the transport's
// payload cipher.
func DialPeer(ep PeerEndpoint, fallbackTransport string, fallbackPort int, password, salt string) (net.Conn, error) {
	t, name, err := ResolvePeerTransport(ep.Transport, fallbackTransport)
	if err != nil {
		return nil, fmt.Errorf("dial peer %s: %w", ep.Addr, err)
	}
	addr := ep.NetworkAddr(fallbackPort)
	if addr == "" {
		return nil, fmt.Errorf("dial peer: empty address")
	}
	logging.Debugf("Mesh: dialing peer %s via %s", addr, name)
	conn, err := t.Dial(addr, password, salt)
	if err != nil {
		return nil, fmt.Errorf("dial peer %s via %s: %w", addr, name, err)
	}
	return conn, nil
}
