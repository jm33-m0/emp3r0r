package transport

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// withTestKey installs a deterministic 32-byte SecureConn key for a test and
// restores the previous one afterwards.
func withTestKey(t *testing.T) {
	t.Helper()
	origKey := def.AESPassword
	def.AESPassword = []byte("12345678901234567890123456789012")
	t.Cleanup(func() { def.AESPassword = origKey })
}

// readRawFrame drains and returns the outer ciphertext length of one frame.
// Draining is required because net.Pipe is synchronous: the writer blocks
// until the whole frame is consumed.
func readRawFrame(t *testing.T, r io.Reader) int {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	dataLen := int(binary.BigEndian.Uint32(hdr[:]))
	if dataLen <= 0 || dataLen > 10*1024*1024 {
		t.Fatalf("nonsensical frame length %d", dataLen)
	}
	body := make([]byte, dataLen)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	return dataLen
}

// TestSecureConnPadsControlFrames pins the ciphertext length for a fixed pad
// range, and confirms the pad actually changes the wire length.
func TestSecureConnPadsControlFrames(t *testing.T) {
	withTestKey(t)
	const pad = 64
	SetC2Padding(pad, pad)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	payload := []byte("padded control frame")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := NewSecureConn(client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sc.Write(payload)
	}()

	// nonce(12) + innerLen(4) + payload + pad + tag(16)
	want := 12 + 4 + len(payload) + pad + 16
	if got := readRawFrame(t, server); got != want {
		t.Fatalf("padded frame length = %d, want %d", got, want)
	}
	<-done
}

// TestSecureConnBulkFrameUnpadded verifies WriteBulk emits the minimum frame.
func TestSecureConnBulkFrameUnpadded(t *testing.T) {
	withTestKey(t)
	SetC2Padding(128, 4096)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	payload := []byte("bulk chunk")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := NewSecureConn(client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sc.WriteBulk(payload)
	}()

	// 12 nonce + 4 innerLen + payload + 16 tag, no pad.
	want := 12 + 4 + len(payload) + 16
	if got := readRawFrame(t, server); got != want {
		t.Fatalf("bulk frame length = %d, want %d", got, want)
	}
	<-done
}

// TestSecureConnLargeFrameSkipsPadding verifies the bulk threshold: a frame
// larger than c2PaddingMaxFrame must not be padded.
func TestSecureConnLargeFrameSkipsPadding(t *testing.T) {
	withTestKey(t)
	SetC2Padding(1024, 4096)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	payload := bytes.Repeat([]byte{0xAB}, c2PaddingMaxFrame+1)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := NewSecureConn(client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sc.Write(payload)
	}()

	want := 12 + 4 + len(payload) + 16
	if got := readRawFrame(t, server); got != want {
		t.Fatalf("large frame length = %d, want %d (must skip padding)", got, want)
	}
	<-done
}

// TestSecureConnStripsPaddingAcrossFrames verifies the receiver removes padding
// and keeps the payload stream intact for consecutive messages.
func TestSecureConnStripsPaddingAcrossFrames(t *testing.T) {
	withTestKey(t)
	SetC2Padding(17, 512)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	first := bytes.Repeat([]byte("A"), 100)
	second := bytes.Repeat([]byte("B"), 4096)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	scClient := NewSecureConn(client)
	scServer := NewSecureConn(server)

	go func() {
		_, _ = scClient.Write(first)
		_, _ = scClient.Write(second)
	}()

	gotFirst := make([]byte, len(first))
	if _, err := io.ReadFull(scServer, gotFirst); err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if !bytes.Equal(gotFirst, first) {
		t.Fatalf("first frame corrupted by padding")
	}
	gotSecond := make([]byte, len(second))
	if _, err := io.ReadFull(scServer, gotSecond); err != nil {
		t.Fatalf("read second frame: %v", err)
	}
	if !bytes.Equal(gotSecond, second) {
		t.Fatalf("second frame corrupted by padding")
	}
}

// TestSecureConnPaddingDisabled verifies 0 disables padding.
func TestSecureConnPaddingDisabled(t *testing.T) {
	withTestKey(t)
	SetC2Padding(0, 0)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	payload := []byte("no padding here")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := NewSecureConn(client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sc.Write(payload)
	}()

	want := 12 + 4 + len(payload) + 16
	if got := readRawFrame(t, server); got != want {
		t.Fatalf("unpadded frame length = %d, want %d", got, want)
	}
	<-done
}

// TestPaddedControlThenBulkFileTransfer mirrors the real C2 file-transfer
// composition: a padded control frame (the MsgAuth envelope), then a gzip'd
// file written through the bulk writer (as SendFile2CC does), all over one
// padded SecureConn. It proves the two frame types interleave without the
// receiver losing or corrupting bulk bytes.
func TestPaddedControlThenBulkFileTransfer(t *testing.T) {
	withTestKey(t)
	SetC2Padding(64, 1024)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	// Large enough to span many bulk frames; compressible like a text file.
	data := bytes.Repeat([]byte("file-transfer-regression-payload-"), 20000)
	authPayload := []byte("control-envelope-bytes")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	scClient := NewSecureConn(client)
	scServer := NewSecureConn(server)

	go func() {
		// Control frame, padded, exactly like EstablishC2Connection's MsgAuth.
		_, _ = scClient.Write(authPayload)
		// Bulk file, unpadded, exactly like SendFile2CC's gzip-over-bulk-writer.
		compressor := gzip.NewWriter(NewBulkWriter(scClient))
		_, _ = compressor.Write(data)
		_ = compressor.Close()
		_ = scClient.Close()
	}()

	gotAuth := make([]byte, len(authPayload))
	if _, err := io.ReadFull(scServer, gotAuth); err != nil {
		t.Fatalf("read padded control frame: %v", err)
	}
	if !bytes.Equal(gotAuth, authPayload) {
		t.Fatalf("control frame corrupted: got %q want %q", gotAuth, authPayload)
	}

	compressed, err := io.ReadAll(scServer)
	if err != nil {
		t.Fatalf("read bulk stream: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("bulk stream is not valid gzip: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompress bulk stream: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("bulk payload mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

// TestSecureConnSkipsEmptyPayloadFrames guards the zero-length frame path: a
// frame with an empty payload must not surface as a spurious zero-byte Read.
func TestSecureConnSkipsEmptyPayloadFrames(t *testing.T) {
	withTestKey(t)
	SetC2Padding(0, 0)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	scClient := NewSecureConn(client)
	scServer := NewSecureConn(server)

	want := []byte("after empty frame")
	go func() {
		_, _ = scClient.WriteBulk(nil)
		_, _ = scClient.WriteBulk(want)
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(scServer, got); err != nil {
		t.Fatalf("read after empty frame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestBulkWriterSkipsPaddingAndUnwraps verifies the bulk wrapper both bypasses
// padding and is transparent to NewSecureConn (no double encryption layer).
func TestBulkWriterSkipsPaddingAndUnwraps(t *testing.T) {
	withTestKey(t)
	SetC2Padding(256, 256)
	t.Cleanup(func() { SetC2Padding(0, 0) })

	base := NewSecureConn(nopReadWriteCloser{})
	bulk := NewBulkWriter(base)
	if _, ok := bulk.(*BulkConn); !ok {
		t.Fatalf("NewBulkWriter over *SecureConn returned %T, want *BulkConn", bulk)
	}
	if got := NewSecureConn(bulk); got != base {
		t.Fatalf("NewSecureConn did not unwrap BulkConn: got %p want %p", got, base)
	}

	payload := []byte("bulk")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sc := NewSecureConn(client)
	wrapped := NewBulkWriter(sc)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = wrapped.Write(payload)
	}()
	want := 12 + 4 + len(payload) + 16
	if got := readRawFrame(t, server); got != want {
		t.Fatalf("BulkConn frame length = %d, want %d", got, want)
	}
	<-done
}
