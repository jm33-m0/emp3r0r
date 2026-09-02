package server

import (
	"bytes"
	"strconv"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// pfsSessionKeys remembers, per agent UUID, the ephemeral PFS session key that
// the agent negotiated with the C2 on its message tunnel.
//
// Every C2 stream is bootstrapped with a static per-build PSK derived from the
// embedded MagicString (def.AESPassword): the check-in stream and the first
// message-tunnel handshake are encrypted with it. Once the tunnel handshake
// derives the ephemeral session key, auxiliary streams (FTP uploads, WWW
// downloads, proxy relay) opened by the same agent are re-keyed to that key
// right after their MsgAuth envelope, so ALL post-handshake traffic — tunnel
// payloads and one-shot streams alike — uses the PFS key instead of the
// static PSK.
//
// These keys are ephemeral by design: they live in memory only (never in the
// agent DB) and are dropped the moment the owning tunnel is torn down.
var pfsSessionKeys sync.Map // agentUUID -> []byte

// rememberPFSSessionKey records (or replaces) the ephemeral PFS session key of
// an agent. It is called right before the handshake reply is sent back, so the
// C2 is ready to decrypt auxiliary streams as soon as the agent completes the
// exchange.
func rememberPFSSessionKey(agentUUID string, key []byte) {
	if agentUUID == "" || len(key) == 0 {
		return
	}
	cpy := make([]byte, len(key))
	copy(cpy, key)
	pfsSessionKeys.Store(agentUUID, cpy)
}

// lookupPFSSessionKey returns the ephemeral PFS session key currently
// registered for an agent, if any.
func lookupPFSSessionKey(agentUUID string) ([]byte, bool) {
	v, ok := pfsSessionKeys.Load(agentUUID)
	if !ok {
		return nil, false
	}
	key, ok := v.([]byte)
	if !ok || len(key) == 0 {
		pfsSessionKeys.Delete(agentUUID)
		return nil, false
	}
	return key, true
}

// forgetPFSSessionKey drops the registered session key of an agent. When key
// is non-nil it is only dropped if it still matches, so the teardown of an old
// tunnel can never wipe the freshly negotiated key of a newer session that
// races it.
func forgetPFSSessionKey(agentUUID string, key []byte) {
	if agentUUID == "" {
		return
	}
	if v, ok := pfsSessionKeys.Load(agentUUID); ok {
		if stored, ok := v.([]byte); ok && (len(key) == 0 || bytes.Equal(stored, key)) {
			pfsSessionKeys.Delete(agentUUID)
		}
	}
}

// maybeRekeyAuxStream switches a post-handshake (auxiliary) stream to the
// agent's ephemeral PFS session key immediately after its MsgAuth envelope has
// been read and verified by the dispatcher. Check-in and the message tunnel
// are bootstrap routes and are never re-keyed here: they run the pre-handshake
// protocol on the static per-build PSK.
func maybeRekeyAuxStream(service string, secureConn *transport.SecureConn, agentUUID string) {
	if service == live.RuntimeConfig.C2Routes.Checkin || service == live.RuntimeConfig.C2Routes.Msg {
		return
	}
	key, ok := lookupPFSSessionKey(agentUUID)
	if !ok {
		return
	}
	secureConn.SetKey(key)
	logging.Debugf("cborProtocolDispatch: %s stream for %s switched to ephemeral PFS session key",
		service, strconv.Quote(agentUUID))
}
