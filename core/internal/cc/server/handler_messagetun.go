package server

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
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
	var (
		lastHandshake int64
		err           error
	)
	atomic.StoreInt64(&lastHandshake, time.Now().Unix())

	ctx, cancel := context.WithCancel(baseCtx)
	if logging.Level >= 4 {
		logging.Debugf("handleMessageTunnel: stream start uuid=%s remote=%s", util.AgentRef(initialAgentUUID), remoteAddr)
	}
	// Track PFS state for this connection
	var (
		pfsEstablished    bool
		establishedPFSKey []byte // current ephemeral session key of this tunnel
	)
	var wg sync.WaitGroup
	defer func() {
		logging.Debugf("handleMessageTunnel exiting")
		cancel() // Signal goroutine to stop
		// Drop the ephemeral PFS key before tearing the session down. Guarded by
		// key equality so the teardown of this tunnel never wipes a newer session
		// key that may have been negotiated by a racing reconnect.
		forgetPFSSessionKey(authAgentUUID, establishedPFSKey)
		// Close the connection BEFORE waiting for the read goroutine.
		// The goroutine blocks on dec.Decode() reading from this conn, so
		// without closing first wg.Wait() would deadlock until the agent
		// happens to send another frame (e.g. a command response).
		_ = secureConn.Close()
		wg.Wait() // Wait for goroutine to finish before returning

		agent, ctrl, found := agents.RuntimeControlByConn(secureConn)
		if !found {
			// The agent may have been admitted but never sent a frame on this
			// tunnel (e.g. operator idle teardown before the first hello). In
			// that case ctrl.Conn is still nil and RuntimeControlByConn cannot
			// find it; fall back to the authenticated UUID so it is removed
			// from the operator-facing list instead of showing a stale,
			// ever-growing LastSeen.
			agent, ctrl, found = agents.RuntimeControlByUUID(authAgentUUID)
			if found && ctrl != nil && ctrl.Conn != nil && ctrl.Conn != secureConn {
				found = false // another live tunnel owns this agent
			}
		}
		if logging.Level >= 4 {
			ctrlConnNil := ctrl == nil || ctrl.Conn == nil
			logging.Debugf("handleMessageTunnel: teardown uuid=%s found=%v ctrlConnNil=%v", util.AgentRef(authAgentUUID), found, ctrlConnNil)
		}
		if found {
			if endErr := agents.EndSession(agent.UUID); endErr != nil {
				logging.Debugf("handleMessageTunnel: end session for %s failed: %v", util.AgentRef(agent.UUID), endErr)
			}
			// Keep the agent visible while it is in a masked sleep. The
			// delayed expiry removes it only if it does not reconnect.
			publishAgentOffline(agent)
		}
		logging.Debugf("handleMessageTunnel exited")
	}()

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
					logging.Warningf("handleMessageTunnel: MsgAuth verify failed from %s: %v", remoteAddr, err)
					return
				}
				if initialAgentUUID != "" && msgAuth.AgentUUID != initialAgentUUID {
					logging.Warningf("handleMessageTunnel: MsgAuth UUID %s does not match stream UUID %s", util.AgentRef(msgAuth.AgentUUID), util.AgentRef(initialAgentUUID))
					return
				}

				now := time.Now().Unix()
				nonceKey := msgAuth.AgentUUID + ":" + msgAuth.Nonce
				if prev, loaded := replayNonceCache.Load(nonceKey); loaded {
					if prevTS, okTS := prev.(int64); okTS && abs64(now-prevTS) <= transport.ReplayWindowSeconds {
						logging.Warningf("handleMessageTunnel: MsgAuth replay detected for %s", util.AgentRef(msgAuth.AgentUUID))
						return
					}
				}
				replayNonceCache.Store(nonceKey, msgAuth.Timestamp)

				authAgentUUID = msgAuth.AgentUUID
				if agents.AgentDB == nil {
					logging.Errorf("handleMessageTunnel: AgentDB unavailable for trust decision")
					return
				}
				pinnedKey, pinnedUUIDSig, found, lookupErr := agents.GetPinnedIdentity(authAgentUUID)
				if lookupErr != nil {
					logging.Errorf("handleMessageTunnel: MsgAuth trust lookup failed for %s: %v", util.AgentRef(authAgentUUID), lookupErr)
					return
				}
				if !found {
					logging.Warningf("handleMessageTunnel: MsgAuth unknown agent %s", util.AgentRef(authAgentUUID))
					return
				}
				if pinnedUUIDSig != "" && msgAuth.IdentityToken != "" && pinnedUUIDSig != msgAuth.IdentityToken {
					logging.Warningf("handleMessageTunnel: MsgAuth token mismatch for %s", util.AgentRef(authAgentUUID))
					return
				}
				if pinnedKey == "" {
					logging.Warningf("handleMessageTunnel: MsgAuth missing pinned key for %s", util.AgentRef(authAgentUUID))
					return
				}
				if msgAuth.AgentProof == "" {
					logging.Warningf("handleMessageTunnel: MsgAuth missing agent proof for %s", util.AgentRef(authAgentUUID))
					return
				}
				proof, decodeErr := base64.URLEncoding.DecodeString(msgAuth.AgentProof)
				if decodeErr != nil {
					logging.Warningf("handleMessageTunnel: MsgAuth bad proof encoding for %s: %v", util.AgentRef(authAgentUUID), decodeErr)
					return
				}
				canonical := transport.CanonicalAuthString(msgAuth.AgentUUID, msgAuth.Timestamp, msgAuth.Nonce, msgAuth.Route)
				proofOK, proofErr := transport.VerifySignatureWithPEM([]byte(pinnedKey), []byte(canonical), proof)
				if proofErr != nil || !proofOK {
					logging.Warningf("handleMessageTunnel: MsgAuth pinned key proof failed for %s: %v", util.AgentRef(authAgentUUID), proofErr)
					return
				}

				seenAt := time.Now()
				atomic.StoreInt64(&lastHandshake, seenAt.Unix())
				agents.MarkAgentSeenByUUID(authAgentUUID, seenAt)
				if agent := agents.GetAgentByUUID(authAgentUUID); agent != nil {
					if err := agents.UpdateAgentLastSeen(agent.UUID, seenAt); err != nil {
						logging.Warningf("handleMessageTunnel: persist last_seen for %s failed: %v", util.AgentRef(agent.UUID), err)
					}
				}
				if logging.Level >= 4 {
					logging.Debugf("handleMessageTunnel: MsgAuth keepalive uuid=%s lastHandshake=%d", util.AgentRef(authAgentUUID), seenAt.Unix())
				}

				continue
			}

			var msg def.MsgTunData
			err = cbor.Unmarshal(raw, &msg)
			if err != nil {
				logging.Warningf("handleMessageTunnel: decode MsgTunData failed: %v", err)
				return
			}
			if authAgentUUID == "" {
				logging.Warningf("handleMessageTunnel: MsgTunData received before MsgAuth")
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

			// The operator-facing identifier is derived exclusively from the
			// authenticated UUID; never trust the TAG the agent sent.
			agent.Tag = util.GenAgentTag(authAgentUUID)
			msg.Tag = agent.Tag

			// Agent authentication is payload-authoritative via MsgAuth.
			// Announce an agent only once per registry lifetime. Reconnects after
			// a masked sleep, and re-check-ins, must stay silent.
			existing, known := live.LookupAgent(agent.UUID)
			announce := !known || !existing.Announced
			rec := &live.AgentRecord{Agent: agent}
			if known {
				rec.Announced = existing.Announced
				if existing.Control != nil {
					cp := *existing.Control
					rec.Control = &cp
				}
			}
			if rec.Control == nil {
				rec.Control = &live.AgentControl{Index: agents.AssignAgentIndex()}
			}
			if announce {
				_ = operatorBroadcastPrintf(logging.SUCCESS, "%s", agentConnectedNotice(agent))
				rec.Announced = true
			}
			now := time.Now()
			agents.MarkAgentSeen(agent, now)
			if logging.Level >= 4 {
				logging.Debugf("handleMessageTunnel: authenticated frame uuid=%s tag=%q cmd=%d resp=%d job=%q", util.AgentRef(authAgentUUID), msg.Tag, len(msg.CmdSlice), len(msg.Response), msg.JobID)
			}
			// Point the copy at this tunnel, then publish it.
			rec.Control.Conn = secureConn
			rec.Control.Ctx = ctx
			rec.Control.Cancel = cancel
			markAgentReconnected(agent.UUID)
			live.PublishAgent(rec)

			// Any authenticated frame (keep-alive hello OR command response)
			// proves the agent is still alive, so refresh the handshake timer
			// here too. Otherwise an agent that answers commands but whose
			// keep-alive loop stalls would be wrongly timed out after 10m.
			atomic.StoreInt64(&lastHandshake, now.Unix())
			if err := agents.UpdateAgentLastSeen(agent.UUID, now); err != nil {
				logging.Warningf("handleMessageTunnel: persist last_seen for %s failed: %v", util.AgentRef(agent.UUID), err)
			}
			if msg.Time > 0 {
				if rtt := time.Since(time.UnixMilli(msg.Time)); rtt >= 0 {
					agents.MarkAgentRTT(agent, rtt)
				}
			}
			// handshake (hello) message has empty CmdSlice or just random data
			// but it's used to tell CC that agent is alive
			// here we just respond to keep-alive if it matches any criteria
			// or if it's explicitly a hello
			if msg.Response == nil && len(msg.CmdSlice) > 0 {
				if logging.Level >= 4 {
					logging.Debugf("handleMessageTunnel: hello received uuid=%s job=%q cmd=%d", util.AgentRef(authAgentUUID), msg.JobID, len(msg.CmdSlice))
				}
				// Check if context is still valid before writing
				if ctx.Err() != nil {
					logging.Debugf("Context cancelled, skipping handshake response")
					return
				}
				// verify hello
				logging.Debugf("Handshake from %s successful", msg.Tag)

				// ECDH Key Exchange Support
				replyData, sessionKey, err := processKeyExchange(authAgentUUID, &msg, pfsEstablished)
				if err != nil {
					logging.Errorf("Handshake processing error: %v", err)
					return
				}

				// Register the ephemeral PFS session key for this agent BEFORE
				// replying: auxiliary streams (FTP/WWW/proxy) the agent opens right
				// after the handshake are re-keyed to it by the dispatcher.
				if sessionKey != nil {
					establishedPFSKey = sessionKey
					rememberPFSSessionKey(authAgentUUID, sessionKey)
				}

				// respond with Server Public Key (or random data), wrapped in MsgTunData
				replyMsg := def.MsgTunData{
					JobID:    msg.JobID,
					Tag:      def.TagHandshake,
					Response: replyData,
				}
				encoder := cbor.NewEncoder(secureConn)
				var enrichedList *def.EnrichedPeerList
				err = encoder.Encode(replyMsg)
				if err == nil {
					if sessionKey != nil {
						// 6. Switch to Session Key (only the initial exchange can yield
						// one — mid-session re-key offers are rejected upstream).
						secureConn.SetKey(sessionKey)
						logging.Infof("SecureConn: Switched to ephemeral session key for %s (PFS enabled)", msg.Tag)
						pfsEstablished = true
					}

					// Only advertise peers to TRUSTED agents (must have established PFS).
					// This ensures the layout is encrypted with the ephemeral session key
					// and we are talking to a successfully authenticated agent.
					if pfsEstablished {
						var collectErr error
						enrichedList, collectErr = collectEnrichedPeerList()
						if collectErr != nil {
							logging.Warningf("handleMessageTunnel: collectEnrichedPeerList for %s: %v", agent.Name, collectErr)
						}
					}
				} else {
					logging.Warningf("handleMessageTunnel: %v", err)
				}

				// Issue AgentToken if missing or expiring within 6 hours.
				// Trust condition: agent has a live MsgTun session (checked-in + communicating).
				// The issued token is cached by UUID (agents.AgentTokenFor) instead of
				// being stored on the shared agent object: this goroutine must not
				// mutate a live.AgentRegistry record that other goroutines snapshot.
				var sessionToken *def.AgentToken
				curToken := agents.AgentTokenFor(authAgentUUID)
				needsToken := curToken == nil ||
					time.Until(time.Unix(curToken.ExpiresAt, 0)) < 6*time.Hour
				if needsToken {
					tok, signErr := SignAgentToken(agent.UUID, agent.From, def.CapabilityRouter, 24*time.Hour)
					if signErr != nil {
						logging.Errorf("handleMessageTunnel: SignAgentToken for %s: %v", agent.Name, signErr)
					} else {
						sessionToken = tok
					}
				}

				// One post-handshake frame carries both pieces of session state. The
				// token is processed before the peer list so mesh authorization is in
				// place before discovery starts.
				if err == nil && (enrichedList != nil || sessionToken != nil) {
					sessionMsg := def.MsgTunData{
						Tag:              def.TagSessionInfo,
						EnrichedPeerList: enrichedList,
						AgentToken:       sessionToken,
					}
					if sendErr := encoder.Encode(sessionMsg); sendErr != nil {
						logging.Errorf("handleMessageTunnel: send SessionInfo to %s: %v", agent.Name, sendErr)
					} else {
						if sessionToken != nil {
							agents.StoreAgentToken(authAgentUUID, sessionToken)
						}
						peerCount := 0
						if enrichedList != nil {
							peerCount = len(enrichedList.Peers)
						}
						logging.Infof("Sent SessionInfo to %s (token=%v, peers=%d)", agent.Name, sessionToken != nil, peerCount)
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
				// Job responses whose IDs belong to the CC-internal SOCKS5 pivot
				// are consumed by the socks manager (via live.CmdResultsReady) and
				// are never owned by an operator session — do not treat their
				// arrival as an operator-facing problem.
				socksInternal := strings.HasPrefix(msg.JobID, socksProxyTokenPrefix)
				if _, knownJob := live.CmdTime.Load(msg.JobID); knownJob {
					responseToCache := msg.Response
					if len(responseToCache) > maxCmdResultCacheBytes {
						logging.Warningf("handleMessageTunnel: truncating oversized response for job %s from %d to %d bytes", strconv.Quote(msg.JobID), len(responseToCache), maxCmdResultCacheBytes)
						responseToCache = responseToCache[:maxCmdResultCacheBytes]
					}
					live.CmdResults.Store(msg.JobID, string(responseToCache))
					// Signal any goroutine waiting for this job's result.
					live.SignalCmdResultReady(msg.JobID)
					// persistence
					jobs.HandleOutput(msg.JobID, responseToCache)
				} else if !socksInternal {
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
				if socksInternal {
					logging.Debugf("handleMessageTunnel: SOCKS5 pivot dial failure for job %s", strconv.Quote(msg.JobID))
					continue
				}
				logging.Warningf("no operator owner for job response %s from agent %s", strconv.Quote(msg.JobID), util.AgentRef(authAgentUUID))
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
				logging.Debugf("handleMessageTunnel: ticker uuid=%s operatorOnline=%v operatorActive=%v lastHandshakeAge=%s", util.AgentRef(authAgentUUID), operatorOnlineNow, operatorActive, lastHandshakeAge)
			}
			if !operatorActive {
				if operatorOnlineNow {
					maybeNotifyOperatorIdle()
				}
				logging.Infof("handleMessageTunnel: operator offline/idle, closing tunnel for agent %s", util.AgentRef(authAgentUUID))
				return
			}
			if lastHandshakeAge > handshakeTimeout {
				operatorBroadcastPrintf(logging.WARN, "handleMessageTunnel: timeout for agent %s", util.AgentRef(authAgentUUID))
				return
			}
		}
	}
}
