package operator

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

type relayFTPConn struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
	buf    []byte
}

func newRelayFTPConn() *relayFTPConn {
	return &relayFTPConn{
		ch:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

func (c *relayFTPConn) Read(p []byte) (int, error) {
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

func (c *relayFTPConn) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("relayFTPConn is read-only")
}

func (c *relayFTPConn) Close() error {
	c.once.Do(func() {
		close(c.ch)
		close(c.closed)
	})
	return nil
}

func (c *relayFTPConn) Push(data []byte) error {
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

var ftpRelayConns sync.Map // map[token]*relayFTPConn

func getOrCreateFTPRelay(token string) (*relayFTPConn, error) {
	if val, ok := ftpRelayConns.Load(token); ok {
		if conn, castOK := val.(*relayFTPConn); castOK && conn != nil {
			return conn, nil
		}
	}

	streamVal, ok := network.FTPStreams.Load("token:" + token)
	if !ok {
		return nil, fmt.Errorf("ftp relay token %q not registered locally", token)
	}
	sh, ok := streamVal.(*network.StreamHandler)
	if !ok || sh == nil {
		return nil, fmt.Errorf("ftp relay token %q has invalid stream handler", token)
	}
	if sh.OperatorSession == "" {
		sh.OperatorSession = client.SessionID
	}

	conn := newRelayFTPConn()
	actual, loaded := ftpRelayConns.LoadOrStore(token, conn)
	if loaded {
		return actual.(*relayFTPConn), nil
	}

	go ftp.HandleFTPStream(conn, token, "relay", func() {})
	return conn, nil
}

func handleFTPRelayMessage(data *def.MsgTunData) bool {
	if data == nil {
		return false
	}

	tag := data.Tag
	switch {
	case strings.HasPrefix(tag, def.TagFTPRelayDataPrefix):
		token := strings.TrimPrefix(tag, def.TagFTPRelayDataPrefix)
		conn, err := getOrCreateFTPRelay(token)
		if err != nil {
			logging.Errorf("CRITICAL: ftp relay setup failed for token %q: %v", token, err)
			return true
		}
		if err := conn.Push(data.Response); err != nil {
			logging.Errorf("CRITICAL: ftp relay push failed for token %q: %v", token, err)
		}
		return true
	case strings.HasPrefix(tag, def.TagFTPRelayDonePrefix):
		token := strings.TrimPrefix(tag, def.TagFTPRelayDonePrefix)
		if val, ok := ftpRelayConns.LoadAndDelete(token); ok {
			_ = val.(*relayFTPConn).Close()
		}
		return true
	case strings.HasPrefix(tag, def.TagFTPRelayErrorPrefix):
		token := strings.TrimPrefix(tag, def.TagFTPRelayErrorPrefix)
		logging.Errorf("FTP relay failed for token %q: %s", token, string(data.Response))
		if val, ok := ftpRelayConns.LoadAndDelete(token); ok {
			_ = val.(*relayFTPConn).Close()
		}
		return true
	default:
		return false
	}
}
