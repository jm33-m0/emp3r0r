package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

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
func SSHProxyClient(serverAddr string, reverseConns *map[string]context.CancelFunc, ctx context.Context, cancel context.CancelFunc) (err error) {
	// var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("toor"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// calculate ProxyPort
	serverPort, err := strconv.Atoi(strings.Split(serverAddr, ":")[1])
	// this is the reverseProxyPort
	if err != nil {
		return fmt.Errorf("serverPort invalid: %v", err)
	}
	proxyPort := strconv.Itoa((serverPort - 1)) // reverseProxyPort = proxyPort + 1

	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", serverAddr, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %v", err)
	}
	defer conn.Close()

	// Request the remote side to open port 8080 on all interfaces.
	l, err := conn.Listen("tcp", "0.0.0.0:"+proxyPort)
	if err != nil {
		return fmt.Errorf("unable to register tcp forward: %v", err)
	}
	defer l.Close()
	defer cancel()

	reverseConnsList := *reverseConns
	reverseConnsList[serverAddr] = cancel // record this connection
	toAddr := "127.0.0.1:" + proxyPort

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
			return fmt.Errorf("SSHProxyClient finished: %v", err)
		}
		go serveConn(inconn)
	}

	return nil
}
