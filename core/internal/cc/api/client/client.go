package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/posener/h2conn"
)

var (
	// HTTPClient is an HTTP/2 client for the mTLS C2 operator server
	HTTPClient *http.Client

	// RootURL is the root URL of the mTLS C2 operator server
	RootURL string

	// SessionID marks the operator session
	SessionID string

	msgTunConnMu  sync.RWMutex
	msgTunConn    *h2conn.Conn
	msgTunWriteMu sync.Mutex
	msgTunUpdateCh = make(chan struct{}, 1)
)

func notifyMsgTunUpdate() {
	select {
	case msgTunUpdateCh <- struct{}{}:
	default:
	}
}

// SendMsgTunData sends a CBOR message through the active operator message tunnel.
func SendMsgTunData(msg *def.MsgTunData) error {
	if msg == nil {
		return fmt.Errorf("nil message")
	}

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	var lastErr error

	for {
		msgTunConnMu.RLock()
		conn := msgTunConn
		msgTunConnMu.RUnlock()

		if conn == nil {
			lastErr = fmt.Errorf("message tunnel is not connected")
			select {
			case <-msgTunUpdateCh:
				continue
			case <-timeout.C:
				return lastErr
			}
		}

		msgTunWriteMu.Lock()
		err := cbor.NewEncoder(conn).Encode(msg)
		msgTunWriteMu.Unlock()

		if err == nil {
			return nil
		}

		lastErr = fmt.Errorf("encode msg tunnel data: %w", err)

		// If this connection is stale/closed, clear it so next loop can wait for a fresh tunnel.
		if isTransientTunnelWriteError(err) {
			msgTunConnMu.Lock()
			if msgTunConn == conn {
				msgTunConn = nil
			}
			msgTunConnMu.Unlock()
			notifyMsgTunUpdate()
			select {
			case <-msgTunUpdateCh:
				continue
			case <-timeout.C:
				return lastErr
			}
		}

		// Non-transient error: fail fast.
		return lastErr
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("message tunnel send timeout")
}

func isTransientTunnelWriteError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "deadline exceeded")
}

// SendCBORRequest sends a POST request with CBOR encoded data and returns the response body
func SendCBORRequest(urlPath string, data any) ([]byte, error) {
	// Encode data to CBOR
	cborData, err := cbor.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	// Create request with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/%s", RootURL, urlPath)

	// Send HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(cborData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Add("operator_session", SessionID)

	if HTTPClient == nil {
		return nil, fmt.Errorf("HTTPClient is nil")
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed, status code: %d, url: %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// ConnectMsgTun connects to the operator message tunnel
func ConnectMsgTun() (conn *h2conn.Conn, ctx context.Context, cancel context.CancelFunc, err error) {
	h2 := h2conn.Client{
		Client: HTTPClient,
		Header: http.Header{
			"operator_session": {SessionID},
		},
	}
	url := fmt.Sprintf("%s/%s", RootURL, transport.OperatorMsgTunnel)
	ctx, cancel = context.WithCancel(context.Background())
	conn, resp, err := h2.Connect(ctx, url)
	if err != nil {
		err = fmt.Errorf("connect to message tunnel: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status code: %d", resp.StatusCode)
		return
	}

	return
}

// StartMessageTunnel starts the background message tunnel handler
func StartMessageTunnel(onData func(*def.MsgTunData), onError func(error)) {
	time.Sleep(3 * time.Second)
	retryDelay := 5 * time.Second
	maxRetryDelay := 5 * time.Minute

	for {
		conn, ctx, cancel, err := ConnectMsgTun()
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("Relay connection failed: %v", err))
			}
			time.Sleep(retryDelay)
			// Exponential backoff
			retryDelay *= 2
			if retryDelay > maxRetryDelay {
				retryDelay = maxRetryDelay
			}
			continue
		}

		decoder := cbor.NewDecoder(bufio.NewReader(conn))
		msgTunConnMu.Lock()
		msgTunConn = conn
		msgTunConnMu.Unlock()
		notifyMsgTunUpdate()

		// Channel to receive decode results
		msgCh := make(chan *def.MsgTunData, 10)
		errCh := make(chan error, 1)

		// Single goroutine to continuously read messages
		go func() {
			for {
				msg := new(def.MsgTunData)
				if err := decoder.Decode(msg); err != nil {
					errCh <- err
					return
				}
				msgCh <- msg
			}
		}()

		// Keep reading messages from the tunnel
		connectionBroken := false

		for ctx.Err() == nil {
			select {
			case msg := <-msgCh:
				onData(msg)
				// Reset retry delay on successful message
				retryDelay = 5 * time.Second
			case err := <-errCh:
				if onError != nil {
					onError(err)
				}
				connectionBroken = true
				goto reconnect
			case <-ctx.Done():
				goto reconnect
			}
		}

	reconnect:
		msgTunConnMu.Lock()
		if msgTunConn == conn {
			msgTunConn = nil
		}
		msgTunConnMu.Unlock()
		notifyMsgTunUpdate()
		cancel()
		conn.Close()

		if connectionBroken {
			time.Sleep(retryDelay)
			// Exponential backoff
			retryDelay *= 2
			if retryDelay > maxRetryDelay {
				retryDelay = maxRetryDelay
			}
		} else {
			time.Sleep(retryDelay)
		}
	}
}
