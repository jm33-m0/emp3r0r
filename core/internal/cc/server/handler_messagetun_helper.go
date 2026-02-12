package server

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// processKeyExchange handles the ECDH key exchange and session key derivation.
func processKeyExchange(msg *def.MsgTunData, pfsEstablished bool) (replyData []byte, sessionKey []byte, err error) {
	if len(msg.EphemPublicKey) > 0 {
		// 1. Generate Server Ephemeral Key Pair
		serverPrivKey, err := transport.GenerateEphemeralKeyPair()
		if err != nil {
			logging.Errorf("Handshake error: failed to generate ephemeral key: %v", err)
			return nil, nil, err
		}

		// 2. Parse Agent's Public Key
		agentPubKey, err := transport.DeserializePublicKey(msg.EphemPublicKey)
		if err != nil {
			logging.Errorf("Handshake error: failed to deserialize agent public key: %v", err)
			return nil, nil, err
		}

		// 3. Derive Shared Secret
		sharedSecret, err := transport.PerformECDH(serverPrivKey, agentPubKey)
		if err != nil {
			logging.Errorf("Handshake error: failed to perform ECDH: %v", err)
			return nil, nil, err
		}

		// 4. Derive Session Key
		sessionKey, err = transport.DeriveSessionKey(sharedSecret, msg.AgentUUID)
		if err != nil {
			logging.Errorf("Handshake error: failed to derive session key: %v", err)
			return nil, nil, err
		}

		// 5. Prepare Response (Server Public Key)
		replyData = transport.SerializePublicKey(&serverPrivKey.PublicKey)
		logging.Infof("Key Exchange: Deriving session key for %s (PFS)", msg.Tag)
	} else {
		// No public key provided
		if pfsEstablished {
			// Already established PFS, just a keep-alive
			replyData = util.RandBytes(util.RandInt(10, 100))
			logging.Debugf("Keep-alive from %s (PFS active)", msg.Tag)
		} else {
			// Legacy / Fallback: random data
			replyData = util.RandBytes(util.RandInt(10, 100))
			logging.Warningf("Key Exchange: Agent %s did not provide ephemeral key, using legacy connection", msg.Tag)
		}
	}
	return replyData, sessionKey, nil
}

// operatorBroadcastPrintf broadcasts a message to all connected operators.
func operatorBroadcastPrintf(msg_type, format string, a ...any) (err error) {
	msgTunData := def.MsgTunData{
		Tag:      msg_type,                          // tell operator about the message type: INFO, WARN, ERROR, SUCCESS
		Response: []byte(fmt.Sprintf(format, a...)), // message content
		JobID:    "",
		CmdSlice: []string{},
	}
	return fwdMsg2Operators(msgTunData)
}

// fwdMsg2Operators forwards a message to all connected operator sessions.
func fwdMsg2Operators(msg def.MsgTunData) (err error) {
	OPERATORS.Range(func(id, value interface{}) bool {
		op, ok := value.(*operator_t)
		if !ok || op == nil || op.conn == nil {
			return true // continue iteration
		}
		encoder := cbor.NewEncoder(op.conn)
		err = encoder.Encode(msg)
		if err != nil {
			logging.Errorf("Failed to forward message to operator: %v", err)
			return false // stop iteration on error
		}
		return true // continue iteration
	})
	return
}
