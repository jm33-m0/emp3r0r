package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

// SSHRemoteFwdServer start a ssh proxy server that forward to client side TCP port
// port: binding port on server side, ssh client will try authentication with this port
// password: ssh client will try authentication with this password.
// We will always use RuntimeConfig.ShadowsocksPassword
func SSHRemoteFwdServer(port, password string, hostkey []byte) (err error) {
	LogInfo("Starting ssh remote forwarding server on port %s...", port)
	forwardHandler := &gliderssh.ForwardedTCPHandler{}
	server := gliderssh.Server{
		PasswordHandler: func(ctx gliderssh.Context, pass string) bool {
			LogInfo("ssh client try to authenticate with password %s", pass)
			success := pass == password
			if success {
				LogInfo("ssh client authenticated")
			}
			return success
		},
		LocalPortForwardingCallback: gliderssh.LocalPortForwardingCallback(func(ctx gliderssh.Context, dhost string, dport uint32) bool {
			LogInfo("Accepted forward %s %d", dhost, dport)
			return true
		}),
		Addr: ":" + port,
		Handler: gliderssh.Handler(func(s gliderssh.Session) {
			// io.WriteString(s, "Remote forwarding available...\n")
			select {}
		}),
		ReversePortForwardingCallback: gliderssh.ReversePortForwardingCallback(func(ctx gliderssh.Context, host string, port uint32) bool {
			LogInfo("attempt to bind %s %d granted", host, port)
			return true
		}),
		RequestHandlers: map[string]gliderssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}
	key, err := ssh.ParsePrivateKey(hostkey)
	if err != nil {
		return fmt.Errorf("failed to parse host key: %v", err)
	}
	server.AddHostKey(key)

	return server.ListenAndServe()
}

// SSHReverseProxyClient dial SSHProxyServer, start a reverse proxy
// serverAddr format: 127.0.0.1:22
func SSHReverseProxyClient(ssh_serverAddr, password string,
	reverseConns *map[string]context.CancelFunc,
	ctx context.Context, cancel context.CancelFunc) (err error) {
	// var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// ignore host key check, this communication happens between agents
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// calculate ProxyPort
	serverPort, err := strconv.Atoi(strings.Split(ssh_serverAddr, ":")[1])
	// this is the reverseProxyPort
	if err != nil {
		return fmt.Errorf("serverPort invalid: %v", err)
	}
	proxyPort := strconv.Itoa((serverPort - 1)) // reverseProxyPort = proxyPort + 1

	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", ssh_serverAddr, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %v", err)
	}
	defer conn.Close()

	// Request the remote side to open proxy port on all interfaces.
	l, err := conn.Listen("tcp", "0.0.0.0:"+proxyPort)
	if err != nil {
		return fmt.Errorf("unable to register tcp forward: %v", err)
	}
	defer l.Close()
	defer cancel()

	reverseConnsList := *reverseConns
	reverseConnsList[ssh_serverAddr] = cancel // record this connection
	toAddr := "127.0.0.1:" + proxyPort

	// forward to socks5
	serveConn := func(clientConn net.Conn) {
		socksConn, err := net.Dial("tcp", toAddr)
		if err != nil {
			LogInfo("failed to connect to socks5 server: %v", err)
			return
		}
		defer socksConn.Close()
		go func() {
			defer clientConn.Close()
			_, err = io.Copy(clientConn, socksConn)
			if err != nil {
				LogInfo("clientConn <- socksConn: %v", err)
			}
		}()
		go func() {
			defer clientConn.Close()
			_, err = io.Copy(socksConn, clientConn)
			if err != nil {
				LogInfo("clientConn -> socksConn: %v", err)
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

// SSHRemoteFwdClient dial SSHRemoteFwdServer, forward local TCP port to remote server
// serverAddr format: 127.0.0.1:22
// hostkey is the ssh server public key
func SSHRemoteFwdClient(ssh_serverAddr, password string,
	hostkey ssh.PublicKey, // ssh server public key
	local_port int, // local port to forward to remote
	conns *map[string]context.CancelFunc, // record this connection
	ctx context.Context, cancel context.CancelFunc) (err error) {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// ignore host key check, this communication happens between agents
		HostKeyCallback: ssh.FixedHostKey(hostkey),
	}

	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", ssh_serverAddr, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %v", err)
	}
	defer conn.Close()
	LogInfo("Connected to ssh server on %s", ssh_serverAddr)

	// Request the remote side to open proxy port on all interfaces.
	l, err := conn.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", local_port))
	if err != nil {
		return fmt.Errorf("unable to register tcp forward: %v", err)
	}
	LogInfo("Forwarding local port %d to remote", local_port)
	defer l.Close()
	defer cancel()

	connsList := *conns
	connsList[ssh_serverAddr] = cancel // record this connection
	toAddr := fmt.Sprintf("127.0.0.1:%d", local_port)

	// forward to target local port
	serveConn := func(conn net.Conn) {
		targetConn, err := net.Dial("tcp", toAddr)
		if err != nil {
			LogInfo("failed to connect to %s: %v", toAddr, err)
			return
		}
		defer targetConn.Close()
		go func() {
			defer conn.Close()
			_, err = io.Copy(conn, targetConn)
			if err != nil {
				LogInfo("clientConn <- targetConn: %v", err)
			}
		}()
		go func() {
			defer conn.Close()
			_, err = io.Copy(targetConn, conn)
			if err != nil {
				LogInfo("clientConn -> targetConn: %v", err)
			}
		}()
		for ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}

	for ctx.Err() == nil {
		inconn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("SSH RemoteFwd (%s) finished: %v", toAddr, err)
		}
		go serveConn(inconn)
	}

	return nil
}
