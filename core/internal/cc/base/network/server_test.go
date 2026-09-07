package network

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// server_test.go — real unit coverage for StreamHandler (the CBOR-encapsulated
// stream object used by FTP relays) plus the server stop helpers.

func TestStreamHandlerWriteCBOREnvelope(t *testing.T) {
	var buf bytes.Buffer
	sh := &StreamHandler{
		Secure:          &buf,
		Token:           "token-abc",
		OperatorSession: "op-1",
	}
	n, err := sh.Write([]byte("payload-bytes"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len("payload-bytes") {
		t.Fatalf("Write reported %d, want %d", n, len("payload-bytes"))
	}

	var msg def.MsgTunData
	if err := cbor.Unmarshal(buf.Bytes(), &msg); err != nil {
		t.Fatalf("Write did not produce CBOR MsgTunData: %v", err)
	}
	if string(msg.Response) != "payload-bytes" {
		t.Fatalf("payload mismatch: %q", msg.Response)
	}
	// The token is used as the routing tag back to the agent.
	if msg.Tag != "token-abc" {
		t.Fatalf("tag = %q, want token-abc", msg.Tag)
	}
}

func TestStreamHandlerWriteWithoutConnFails(t *testing.T) {
	sh := &StreamHandler{}
	if _, err := sh.Write([]byte("x")); err == nil {
		t.Fatal("Write with nil Secure must fail")
	}
}

func TestStreamHandlerReadEOFWhenNoSecure(t *testing.T) {
	sh := &StreamHandler{}
	var one [1]byte
	if _, err := sh.Read(one[:]); err != io.EOF {
		t.Fatalf("Read with nil Secure: err = %v, want EOF", err)
	}
}

func TestStreamHandlerCloseCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sh := &StreamHandler{Cancel: cancel}
	if err := sh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !sh.IsClosed {
		t.Fatal("IsClosed not set by Close")
	}
	if ctx.Err() == nil {
		t.Fatal("Cancel was not invoked by Close")
	}
}
