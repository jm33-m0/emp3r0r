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
			return
		}
	}

	if proxyserver == nil {
		socks5.Debug = true
		proxyserver, err = socks5.NewClassicServer(addr, "", "", "", 10, 10)
		if err != nil {
			return
		}
	} else {
		return fmt.Errorf("Socks5Proxy is already running on %s", proxyserver.ServerAddr.String())
	}

	log.Printf("Socks5Proxy started on %s", addr)
	err = proxyserver.ListenAndServe(nil)
	if err != nil {
		return
	}
	log.Printf("Socks5Proxy stopped (%s)", addr)

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

// FwdToDport forward request to agent-side destination, h2 <-> tcp
func FwdToDport(ctx context.Context, cancel context.CancelFunc,
	to string, sessionID string, h2 *h2conn.Conn) {

	var err error

	// connect to target port
	dest, err := net.Dial("tcp", to)
	defer func() {
		cancel()
		if dest != nil {
			dest.Close()
		}
		log.Printf("FwdToDport %s exited", to)
	}()
	if err != nil {
		log.Printf("FwdToDport %s: %v", to, err)
		return
	}

	// io.Copy
	go func() {
		_, err = io.Copy(dest, h2)
		if err != nil {
			log.Printf("FwdToDport (%s): h2 -> dest: %v", sessionID, err)
			return
		}
	}()
	go func() {
		_, err = io.Copy(h2, dest)
		if err != nil {
			log.Printf("FwdToDport (%s): dest -> h2: %v", sessionID, err)
			return
		}
	}()

	for ctx.Err() == nil {
		time.Sleep(500 * time.Millisecond)
	}
	_, _ = h2.Write([]byte("exit\n"))
	_, _ = dest.Write([]byte("exit\n"))
}

// TCPConnJoin join two TCP connections
func TCPConnJoin(ctx context.Context, cancel context.CancelFunc, addr1, addr2 string) error {
	var err error
	serveConn := func(conn, conn1 net.Conn) {
		// copy conn to CC
		go func() {
			for conn == nil || conn1 == nil {
				time.Sleep(100 * time.Millisecond)
			}
			_, err = io.Copy(conn, conn1)
			if err != nil {
				log.Printf("TCPConnJoin iocopy: conn <- conn1: %v", err)
			}
		}()
		go func() {
			for conn == nil || conn1 == nil {
				time.Sleep(100 * time.Millisecond)
			}
			_, err = io.Copy(conn1, conn)
			if err != nil {
				log.Printf("TCPConnJoin iocopy: conn -> conn1: %v", err)
			}
		}()
		// wait to be canceled
		for ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}

	// wait to be canceled
	for ctx.Err() == nil {
		conn, err := net.Dial("tcp", addr1)
		if err != nil {
			return fmt.Errorf("TCPConnJoin addr1: %v", err)
		}
		// connect to addr2
		conn1, err := net.Dial("tcp", addr2)
		if err != nil {
			return fmt.Errorf("TCPConnJoin addr2: %v", err)
		}
		serveConn(conn, conn1)
		// cleanup
		defer func() {
			conn.Close()
			conn1.Close()
			cancel()
			log.Printf("TCPConnJoin: %s <-> %s ended", addr1, addr2)
		}()

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}
