package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const DefaultC2BlockSize = 32 * 1024

// c2PaddingMaxFrame bounds which frames receive random padding. Bulk stream
// chunks (file transfer, port forwarding) above this size already have
// unpredictable, content-independent lengths; padding them would only add
// bandwidth overhead. Control frames are well under this limit.
const c2PaddingMaxFrame = 32 * 1024

// Padding is a sender-side knob: each frame carries its own payload length, so
// the receiver strips padding without knowing the configured range. Atomically
// accessed because config load sets it while connection goroutines read it.
var (
	c2PaddingMin atomic.Int32
	c2PaddingMax atomic.Int32
)

// SetC2Padding sets the per-frame plaintext padding range in bytes. min<=0
// disables padding and max<min is clamped to min.
func SetC2Padding(min, max int) {
	if min < 0 {
		min = 0
	}
	if max < min {
		max = min
	}
	c2PaddingMin.Store(int32(min))
	c2PaddingMax.Store(int32(max))
}

func (sc *SecureConn) choosePadding(payloadLen int) int {
	if payloadLen <= 0 || payloadLen > c2PaddingMaxFrame {
		return 0
	}
	min := int(c2PaddingMin.Load())
	max := int(c2PaddingMax.Load())
	if min <= 0 {
		return 0
	}
	if max < min {
		max = min
	}
	return util.RandInt(min, max+1)
}

// SecureConn wraps a net.Conn with AES-GCM encryption
type SecureConn struct {
	net.Conn
	key     []byte
	keyMu   sync.RWMutex
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
}

// ByteReadWriteCloser wraps io.ReadWriteCloser to implement net.Conn
// This is a helper to allow wrapping things that aren't strictly net.Conn but act like one
type ByteReadWriteCloser struct {
	io.ReadWriteCloser
}

func (b *ByteReadWriteCloser) LocalAddr() net.Addr                { return nil }
func (b *ByteReadWriteCloser) RemoteAddr() net.Addr               { return nil }
func (b *ByteReadWriteCloser) SetDeadline(t time.Time) error      { return nil }
func (b *ByteReadWriteCloser) SetReadDeadline(t time.Time) error  { return nil }
func (b *ByteReadWriteCloser) SetWriteDeadline(t time.Time) error { return nil }

// NewSecureConn creates a new SecureConn using the global AESPassword if no key is provided.
// If conn is already a *SecureConn it is returned unchanged so callers can safely
// "wrap" a connection that may have been pre-keyed (e.g. switched to an ephemeral
// PFS session key) without adding a second encryption/framing layer.
func NewSecureConn(conn io.ReadWriteCloser) *SecureConn {
	if sc, ok := conn.(*SecureConn); ok {
		return sc
	}
	// A padded-bypass writer wraps the same SecureConn; unwrap it so callers
	// never end up with two encryption layers.
	if bc, ok := conn.(*BulkConn); ok {
		return bc.SecureConn
	}

	// If conn is not a net.Conn, wrap it
	var netConn net.Conn
	var ok bool
	if netConn, ok = conn.(net.Conn); !ok {
		netConn = &ByteReadWriteCloser{conn}
	}

	return &SecureConn{
		Conn:    netConn,
		key:     def.AESPassword, // Use the global key
		readBuf: make([]byte, 0),
	}
}

// BulkConn is a SecureConn whose writes skip per-frame padding. Reads are
// unchanged. It is used for bulk byte relays (file transfer, port forwarding)
// where the payload length is already large and content-independent.
type BulkConn struct {
	*SecureConn
}

// Write skips the random padding applied to control frames.
func (b *BulkConn) Write(p []byte) (int, error) {
	return b.SecureConn.WriteBulk(p)
}

// NewBulkWriter wraps conn so writes skip padding. If conn is not a
// *SecureConn it is returned unchanged.
func NewBulkWriter(conn io.ReadWriteCloser) io.ReadWriteCloser {
	if sc, ok := conn.(*SecureConn); ok {
		return &BulkConn{SecureConn: sc}
	}
	return conn
}

// SetKey updates the encryption key for the connection.
// This is used to switch to a session key after a successful handshake.
func (sc *SecureConn) SetKey(key []byte) {
	sc.keyMu.Lock()
	defer sc.keyMu.Unlock()
	sc.key = key
}

// Read reads encrypted data from the connection, decrypts it, and returns the
// payload. The plaintext frame is [payloadLen (4 bytes BE)][payload][padding];
// the padding is stripped here so upper layers only see payload bytes.
func (sc *SecureConn) Read(p []byte) (n int, err error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

	for {
		// If we have buffered data, return it
		if len(sc.readBuf) > 0 {
			n = copy(p, sc.readBuf)
			sc.readBuf = sc.readBuf[n:]
			return n, nil
		}

		// Read header: 4 bytes length
		header := make([]byte, 4)
		_, err = io.ReadFull(sc.Conn, header)
		if err != nil {
			return 0, err
		}

		// Parse length
		dataLen := int(binary.BigEndian.Uint32(header))

		// Sanity check
		if dataLen <= 0 || dataLen > 10*1024*1024 { // 10MB max chunk
			return 0, fmt.Errorf("read: invalid encrypted chunk length: %d", dataLen)
		}

		// Read encrypted payload
		encryptedData := make([]byte, dataLen)
		_, err = io.ReadFull(sc.Conn, encryptedData)
		if err != nil {
			return 0, err
		}

		// Decrypt
		sc.keyMu.RLock()
		key := sc.key
		sc.keyMu.RUnlock()
		decrypted, err := crypto.AES_GCM_Decrypt_Raw(key, encryptedData)
		if err != nil {
			logging.Errorf("SecureConn: decryption failed: %v", err)
			return 0, err
		}

		// Strip the in-frame length and any padding. The length is authenticated
		// (it lives inside the GCM ciphertext), so a tampered value fails the tag.
		if len(decrypted) < 4 {
			return 0, fmt.Errorf("read: decrypted frame too short: %d", len(decrypted))
		}
		payloadLen := int(binary.BigEndian.Uint32(decrypted[:4]))
		if payloadLen < 0 || payloadLen > len(decrypted)-4 {
			return 0, fmt.Errorf("read: invalid payload length: %d (frame %d)", payloadLen, len(decrypted))
		}
		payload := decrypted[4 : 4+payloadLen]
		if payloadLen == 0 {
			// Do not surface a zero-length frame as a zero-byte Read; skip to
			// the next frame instead so callers never see a spurious EOF-like
			// no-progress result.
			continue
		}

		// Copy to p
		n = copy(p, payload)

		// Buffer remaining
		if n < len(payload) {
			sc.readBuf = payload[n:]
		}

		return n, nil
	}
}

// Write encrypts the data and writes it to the connection with framing. Control
// frames carry random padding so a passive observer cannot map frame length to
// message content; the receiver strips it via the in-frame payload length.
func (sc *SecureConn) Write(p []byte) (n int, err error) {
	return sc.writeFrame(p, sc.choosePadding(len(p)))
}

// WriteBulk writes a frame without random padding. Bulk byte relays use it so
// large transfers are not inflated by per-chunk padding, while keeping the same
// on-wire framing as Write.
func (sc *SecureConn) WriteBulk(p []byte) (int, error) {
	return sc.writeFrame(p, 0)
}

func (sc *SecureConn) writeFrame(p []byte, padLen int) (int, error) {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	sc.keyMu.RLock()
	key := sc.key
	sc.keyMu.RUnlock()

	// Plaintext frame: [payloadLen (4 bytes BE)][payload][random padding].
	plain := make([]byte, 4+len(p)+padLen)
	binary.BigEndian.PutUint32(plain[:4], uint32(len(p)))
	copy(plain[4:], p)
	if padLen > 0 {
		if _, err := rand.Read(plain[4+len(p):]); err != nil {
			return 0, fmt.Errorf("pad frame: %w", err)
		}
	}

	encrypted, err := crypto.AES_GCM_Encrypt_Raw(key, plain)
	if err != nil {
		return 0, fmt.Errorf("encryption failed: %v", err)
	}

	// Frame: [Len (4 bytes)] [Encrypted Data]
	frame := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(encrypted)))
	copy(frame[4:], encrypted)

	written := 0
	for written < len(frame) {
		nw, writeErr := sc.Conn.Write(frame[written:])
		if nw > 0 {
			written += nw
		}
		if writeErr != nil {
			return 0, writeErr
		}
		if nw == 0 {
			return 0, io.ErrShortWrite
		}
	}

	return len(p), nil
}

// Close closes the connection
func (sc *SecureConn) Close() error {
	return sc.Conn.Close()
}

// CopyC2Blocks copies data in explicit fixed-size blocks over the C2 stream.
// Each Write call is framed by SecureConn, so this enforces deterministic block boundaries.
func CopyC2Blocks(dst io.Writer, src io.Reader, blockSize int) (int64, error) {
	if blockSize <= 0 {
		blockSize = DefaultC2BlockSize
	}

	buf := make([]byte, blockSize)
	var written int64

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

// Helpers for manual Encrypt/Decrypt (used by Preflight)
func Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(def.AESPassword)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(def.AESPassword)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
