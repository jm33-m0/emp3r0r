package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/ncruces/go-dns"
	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

// StartSocks5Proxy sock5 proxy server on agent, listening on addr
func StartSocks5Proxy(addr, doh string, proxyserver *socks5.Server) (err error) {
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
	LogInfo("Socks5Proxy started on %s", addr)
	err = proxyserver.ListenAndServe(nil)
	if err != nil {
		return fmt.Errorf("Socks5Proxy listen: %v", err)
	}
	LogInfo("Socks5Proxy stopped (%s)", addr)

	return
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
			time.Sleep(time.Duration(20) * time.Millisecond)
		}
	}
	log.Printf("[+] Serving %s on 0.0.0.0:%s...", addr, port)
	l, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Printf("unable to listen on 0.0.0.0:%s: %v", port, err)
		return
	}
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

// FwdToDport forward request to agent-side destination, h2 <-> tcp/udp
func FwdToDport(ctx context.Context, cancel context.CancelFunc,
	to, sessionID, protocol string, h2 *h2conn.Conn, timeout int) {

	var err error

	// connect to target port
	dest, err := net.Dial(protocol, to)
	defer func() {
		if dest != nil {
			dest.Close()
		}
		cancel()
		log.Printf("FwdToDport %s (%s) exited", to, protocol)
	}()
	if err != nil {
		log.Printf("FwdToDport %s (%s): %v", to, protocol, err)
		return
	}
	log.Printf("FwdToDport: connected to %s (%s)", to, protocol)

	// io.Copy
	go func() {
		_, err = io.Copy(dest, h2)
		if err != nil {
			log.Printf("FwdToDport %s (%s): h2 -> dest: %v", protocol, sessionID, err)
			return
		}
	}()
	_, err = io.Copy(h2, dest)
	if err != nil {
		log.Printf("FwdToDport %s (%s): dest -> h2: %v", protocol, sessionID, err)
		return
	}
}
