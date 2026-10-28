package def

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAgentConfigSlotRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("ciphertext"),
		[]byte("ciphertext\x00"),
		[]byte("ciphertext\x00\x00\x00"),
		bytes.Repeat([]byte{0x00}, 16),
	}
	for _, ciphertext := range cases {
		slot, err := PackAgentConfig(ciphertext)
		if err != nil {
			t.Fatalf("PackAgentConfig(%x): %v", ciphertext, err)
		}
		if len(slot) != len(AgentConfig) {
			t.Fatalf("slot length = %d, want %d", len(slot), len(AgentConfig))
		}
		got, err := UnpackAgentConfig(slot)
		if err != nil {
			t.Fatalf("UnpackAgentConfig(%x): %v", ciphertext, err)
		}
		if !bytes.Equal(got, ciphertext) {
			t.Fatalf("round trip = %x, want %x", got, ciphertext)
		}
	}
}

func TestPackAgentConfigRejectsInvalid(t *testing.T) {
	if _, err := PackAgentConfig(nil); err == nil {
		t.Fatal("PackAgentConfig(nil) succeeded, want error")
	}
	tooLarge := make([]byte, len(AgentConfig)-AgentConfigHeaderSize+1)
	if _, err := PackAgentConfig(tooLarge); err == nil {
		t.Fatal("PackAgentConfig(oversized) succeeded, want error")
	}
}

func TestUnpackAgentConfigRejectsInvalid(t *testing.T) {
	short := make([]byte, AgentConfigHeaderSize-1)
	if _, err := UnpackAgentConfig(short); err == nil {
		t.Fatal("UnpackAgentConfig(short slot) succeeded, want error")
	}

	zero := make([]byte, len(AgentConfig))
	if _, err := UnpackAgentConfig(zero); err == nil {
		t.Fatal("UnpackAgentConfig(unpatched slot) succeeded, want error")
	}

	tooLong := make([]byte, len(AgentConfig))
	binary.BigEndian.PutUint32(tooLong[:AgentConfigHeaderSize], uint32(len(tooLong)))
	if _, err := UnpackAgentConfig(tooLong); err == nil {
		t.Fatal("UnpackAgentConfig(oversized length) succeeded, want error")
	}
}
