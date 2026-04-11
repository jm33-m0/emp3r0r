package operator

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

type relayProxyConn struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
	buf    []byte
	token  string
}

func newRelayProxyConn(token string) *relayProxyConn {
	return &relayProxyConn{
		ch:     make(chan []byte, 64),
		closed: make(chan struct{}),
		token:  token,
	}
}

func (c *relayProxyConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		chunk, ok := <-c.ch
		if !ok {
			return 0, io.EOF
		}
		c.buf = chunk
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *relayProxyConn) Write(p []byte) (int, error) {
	msg := &def.MsgTunData{Tag: def.TagProxyRelayBackPrefix + c.token, Response: p}
	if err := client.SendMsgTunData(msg); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *relayProxyConn) Close() error {
	c.once.Do(func() {
		close(c.ch)
		close(c.closed)
	})
	return nil
}

func (c *relayProxyConn) Push(data []byte) error {
	select {
	case <-c.closed:
		return io.EOF
	default:
	}
	chunk := make([]byte, len(data))
	copy(chunk, data)
	c.ch <- chunk
	return nil
}

var proxyRelayConns sync.Map // map[token]*relayProxyConn

func getOrCreateProxyRelay(token string) (*relayProxyConn, error) {
	if val, ok := proxyRelayConns.Load(token); ok {
		if conn, castOK := val.(*relayProxyConn); castOK && conn != nil {
			return conn, nil
		}
	}

	conn := newRelayProxyConn(token)
	actual, loaded := proxyRelayConns.LoadOrStore(token, conn)
	if loaded {
		return actual.(*relayProxyConn), nil
	}

	go network.HandlePortFwdStream(&network.StreamHandler{}, conn, "relay-agent", token, "relay", func() {})
	return conn, nil
}

func handleProxyRelayMessage(data *def.MsgTunData) bool {
	if data == nil {
		return false
	}

	tag := data.Tag
	switch {
	case strings.HasPrefix(tag, def.TagProxyRelayDataPrefix):
		token := strings.TrimPrefix(tag, def.TagProxyRelayDataPrefix)
		conn, err := getOrCreateProxyRelay(token)
		if err != nil {
			logging.Errorf("CRITICAL: proxy relay setup failed for token %q: %v", token, err)
			return true
		}
		if err := conn.Push(data.Response); err != nil {
			logging.Errorf("CRITICAL: proxy relay push failed for token %q: %v", token, err)
		}
		return true
	case strings.HasPrefix(tag, def.TagProxyRelayDonePrefix):
		token := strings.TrimPrefix(tag, def.TagProxyRelayDonePrefix)
		if val, ok := proxyRelayConns.LoadAndDelete(token); ok {
			_ = val.(*relayProxyConn).Close()
		}
		return true
	case strings.HasPrefix(tag, def.TagProxyRelayErrorPrefix):
		token := strings.TrimPrefix(tag, def.TagProxyRelayErrorPrefix)
		logging.Errorf("Proxy relay failed for token %q: %s", token, string(data.Response))
		if val, ok := proxyRelayConns.LoadAndDelete(token); ok {
			_ = val.(*relayProxyConn).Close()
		}
		return true
	default:
		return false
	}
}

func closeProxyRelay(token string) {
	if token == "" {
		return
	}
	if val, ok := proxyRelayConns.LoadAndDelete(token); ok {
		_ = val.(*relayProxyConn).Close()
	}
	_ = client.SendMsgTunData(&def.MsgTunData{Tag: def.TagProxyRelayDonePrefix + token})
}

func validateProxyToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("empty proxy relay token")
	}
	return nil
}
