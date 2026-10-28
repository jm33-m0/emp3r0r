package def

import (
	"encoding/binary"
	"fmt"
)

// AgentConfigHeaderSize is the size of the length prefix in the agent's
// fixed-size embedded config slot.
//
// The slot is laid out as:
//
//	[big-endian uint32 ciphertext length][ciphertext][zero padding]
//
// The length prefix makes the ciphertext boundary unambiguous. Zero padding
// alone is not enough: AES-GCM output is random, so it may legitimately end in
// one or more zero bytes, and trimming those on the agent side corrupts the
// tag. Every producer/consumer of the Go agent's config slot must use these
// helpers.
const AgentConfigHeaderSize = 4

// PackAgentConfig writes an encrypted config into the fixed-size slot.
func PackAgentConfig(ciphertext []byte) ([]byte, error) {
	capacity := len(AgentConfig) - AgentConfigHeaderSize
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("agent config: empty ciphertext")
	}
	if len(ciphertext) > capacity {
		return nil, fmt.Errorf("agent config: %d bytes exceeds slot capacity %d", len(ciphertext), capacity)
	}

	slot := make([]byte, len(AgentConfig))
	binary.BigEndian.PutUint32(slot[:AgentConfigHeaderSize], uint32(len(ciphertext)))
	copy(slot[AgentConfigHeaderSize:], ciphertext)
	return slot, nil
}

// UnpackAgentConfig returns the ciphertext stored in the fixed-size slot.
func UnpackAgentConfig(slot []byte) ([]byte, error) {
	if len(slot) < AgentConfigHeaderSize {
		return nil, fmt.Errorf("agent config: slot too short (%d bytes)", len(slot))
	}

	length := binary.BigEndian.Uint32(slot[:AgentConfigHeaderSize])
	if length == 0 {
		return nil, fmt.Errorf("agent config: empty ciphertext")
	}
	if int(length) > len(slot)-AgentConfigHeaderSize {
		return nil, fmt.Errorf("agent config: length %d exceeds slot of %d bytes", length, len(slot))
	}

	return slot[AgentConfigHeaderSize : AgentConfigHeaderSize+int(length)], nil
}
