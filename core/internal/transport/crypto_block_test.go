package transport

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestCopyC2Blocks_RoundTripOverSecureConn(t *testing.T) {
	origKey := def.AESPassword
	def.AESPassword = []byte("1234567890123456")
	defer func() {
		def.AESPassword = origKey
	}()

	srcData := bytes.Repeat([]byte("block-based-c2-stream-"), 8192)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientSecure := NewSecureConn(clientConn)
	serverSecure := NewSecureConn(serverConn)

	sendErrCh := make(chan error, 1)
	go func() {
		_, err := CopyC2Blocks(clientSecure, bytes.NewReader(srcData), 4096)
		if err == nil {
			err = clientSecure.Close()
		}
		sendErrCh <- err
	}()

	recvData, err := io.ReadAll(serverSecure)
	if err != nil {
		t.Fatalf("ReadAll over SecureConn failed: %v", err)
	}
	if !bytes.Equal(recvData, srcData) {
		t.Fatalf("round trip data mismatch: got %d bytes, want %d bytes", len(recvData), len(srcData))
	}

	if sendErr := <-sendErrCh; sendErr != nil {
		t.Fatalf("CopyC2Blocks sender failed: %v", sendErr)
	}
}

func TestCopyC2Blocks_DefaultBlockSizeWhenInvalid(t *testing.T) {
	var dst bytes.Buffer
	srcData := bytes.Repeat([]byte("x"), DefaultC2BlockSize+17)

	n, err := CopyC2Blocks(&dst, bytes.NewReader(srcData), 0)
	if err != nil {
		t.Fatalf("CopyC2Blocks with default block size failed: %v", err)
	}
	if int(n) != len(srcData) {
		t.Fatalf("CopyC2Blocks wrote %d bytes, want %d", n, len(srcData))
	}
	if !bytes.Equal(dst.Bytes(), srcData) {
		t.Fatal("CopyC2Blocks output mismatch")
	}
}

func TestSecureConnRejectsInvalidChunkLength(t *testing.T) {
	origKey := def.AESPassword
	def.AESPassword = []byte("1234567890123456")
	defer func() {
		def.AESPassword = origKey
	}()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	secureReader := NewSecureConn(serverConn)

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte{0x7f, 0xff, 0xff, 0xff})
		if err == nil {
			err = clientConn.Close()
		}
		writeErrCh <- err
	}()

	buf := make([]byte, 1)
	_, err := secureReader.Read(buf)
	if err == nil {
		t.Fatal("expected invalid encrypted chunk length error, got nil")
	}

	if writeErr := <-writeErrCh; writeErr != nil {
		t.Fatalf("failed to write invalid frame header: %v", writeErr)
	}
}
