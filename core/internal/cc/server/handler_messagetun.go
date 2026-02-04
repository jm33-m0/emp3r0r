package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

// handleMessageTunnel processes CBOR C&C tunnel connections.
func handleMessageTunnel(wrt http.ResponseWriter, req *http.Request) {
	var lastHandshake int64
	atomic.StoreInt64(&lastHandshake, time.Now().Unix())
	conn, err := h2conn.Accept(wrt, req)
	if err != nil {
		logging.Errorf("handleMessageTunnel: connection failed from %s: %s", req.RemoteAddr, err)
		http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// Global Encryption: Wrap connection
	secureConn := transport.NewSecureConn(conn)

	ctx, cancel := context.WithCancel(req.Context())
	var wg sync.WaitGroup
	defer func() {
		logging.Debugf("handleMessageTunnel exiting")
		cancel() // Signal goroutine to stop
		wg.Wait() // Wait for goroutine to finish before returning
		live.AgentControlMapMutex.Lock()
		for t, c := range live.AgentControlMap {
			if c.Conn == secureConn {
				delete(live.AgentControlMap, t)
				operatorBroadcastPrintf(logging.ERROR, "Agent dies... %s is disconnected", strconv.Quote(t.Name))
				break
			}
		}
		live.AgentControlMapMutex.Unlock()
		_ = conn.Close()
		logging.Debugf("handleMessageTunnel exited")
	}()
	in := cbor.NewDecoder(secureConn)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for ctx.Err() == nil {
			var msg def.MsgTunData
			err = in.Decode(&msg)
			if err != nil {
				return
			}

			// find agent
			var agent *def.Emp3r0rAgent
			for i := 0; i < 5; i++ {
				// prefer UUID
				if msg.AgentUUID != "" {
					agent = agents.GetAgentByUUID(msg.AgentUUID)
				}
				if agent == nil {
					agent = agents.GetAgentByTag(msg.Tag)
				}
				if agent != nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if agent == nil {
				logging.Errorf("handleMessageTunnel: No agent found for message: %v", msg)
				return
			}

			// verify agent identification (TOFU)
			agent_sig, err := base64.URLEncoding.DecodeString(msg.AgentUUIDSig)
			if err != nil {
				logging.Errorf("handleMessageTunnel: invalid signature encoding from %s: %v", msg.Tag, err)
				return
			}

			// Verify signature using PINNED key
			var pubKeyBytes []byte
			if agent.PublicKey != "" {
				pubKeyBytes = []byte(agent.PublicKey)
			} else {
				// Fallback or error?
				// If agent has no key, we can't verify self-signed signature.
				// For legacy/migration, maybe fetch from CheckIn if checkin happened?
				// But checkin should have populated PublicKey.
				logging.Errorf("handleMessageTunnel: Agent %s has no pinned public key", agent.Tag)
				return
			}

			isValid, err := transport.VerifySignatureWithPEM(pubKeyBytes, []byte(msg.AgentUUID), agent_sig)
			if err != nil || !isValid {
				logging.Errorf("handleMessageTunnel: invalid signature from %s: %v", msg.Tag, err)
				return
			}
			shortname := agent.Name
			live.AgentControlMapMutex.Lock()
			if live.AgentControlMap[agent].Conn == nil {
				operatorBroadcastPrintf(logging.SUCCESS,
					"Knock.. Knock... Agent %s is connected",
					strconv.Quote(shortname))
			}
			live.AgentControlMap[agent].Conn = secureConn
			live.AgentControlMap[agent].Ctx = ctx
			live.AgentControlMap[agent].Cancel = cancel
			live.AgentControlMapMutex.Unlock()

			// handshake (hello) message has empty CmdSlice or just random data
			// but it's used to tell CC that agent is alive
			// here we just respond to keep-alive if it matches any criteria
			// or if it's explicitly a hello
			if msg.Response == nil && len(msg.CmdSlice) > 0 {
				// Check if context is still valid before writing
				if ctx.Err() != nil {
					logging.Debugf("Context cancelled, skipping handshake response")
					return
				}
				// verify hello
				logging.Debugf("Handshake from %s successful", msg.Tag)
				// respond with random data, wrapped in MsgTunData
				replyData := util.RandBytes(util.RandInt(10, 100))
				replyMsg := def.MsgTunData{
					CmdID:    msg.CmdID,
					Tag:      "handshake",
					Response: replyData,
				}
				encoder := cbor.NewEncoder(secureConn)
				err = encoder.Encode(replyMsg)
				if err != nil {
					logging.Warningf("handleMessageTunnel: %v", err)
				}
				atomic.StoreInt64(&lastHandshake, time.Now().Unix())
				continue // Handshake handled, next message
			}

			// if not a handshake, forward message to operators
			// also cache it for automated tests or local usage
			if msg.CmdID != "" {
				live.CmdResults.Store(msg.CmdID, string(msg.Response))
			}
			err = fwdMsg2Operators(msg)
			if err != nil {
				logging.Warningf("handleMessageTunnel: %v", err)
				return
			}
		}
	}()
	for ctx.Err() == nil {
		lastHandshakeTime := time.Unix(atomic.LoadInt64(&lastHandshake), 0)
		if time.Since(lastHandshakeTime) > 2*time.Minute {
			operatorBroadcastPrintf(logging.WARN, "handleMessageTunnel: timeout for agent")
			return
		}
		util.TakeABlink()
	}
}

func operatorBroadcastPrintf(msg_type, format string, a ...any) (err error) {
	msgTunData := def.MsgTunData{
		Tag:      msg_type,                          // tell operator about the message type: INFO, WARN, ERROR, SUCCESS
		Response: []byte(fmt.Sprintf(format, a...)), // message content
		CmdID:    "",
		CmdSlice: []string{},
	}
	return fwdMsg2Operators(msgTunData)
}

func fwdMsg2Operators(msg def.MsgTunData) (err error) {
	for operator_session_id, operator := range OPERATORS {
		if operator == nil {
			continue
		}
		if operator.conn == nil {
			continue
		}
		encoder := cbor.NewEncoder(operator.conn)
		err = encoder.Encode(msg)
		if err != nil {
			logging.Errorf("Failed to forward message to operator: %v", err)
			return
		}
		logging.Debugf("Forwarded message %v to operator %s", msg, operator_session_id)
	}
	return
}
