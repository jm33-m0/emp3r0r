package cc

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

// KCPListenAndServe KCP server for Shadowsocks
func KCPListenAndServe() {
	key := pbkdf2.Key([]byte(RuntimeConfig.ShadowsocksPassword),
		[]byte(emp3r0r_data.MagicString), 1024, 32, sha256.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	if listener, err := kcp.ListenWithOptions("0.0.0.0:"+RuntimeConfig.KCPPort,
		block, 10, 3); err == nil {
		for {
			s, err := listener.AcceptKCP()
			if err != nil {
				log.Fatal(err)
			}
			go fwd2Shadowsocks(s)
		}
	} else {
		log.Fatal(err)
	}
}

// fwd2Shadowsocks send everything to Shadowsocks server
func fwd2Shadowsocks(conn *kcp.UDPSession) {
	ss_addr := fmt.Sprintf("127.0.0.1:%s", RuntimeConfig.ShadowsocksPort)
	ss_conn, err := net.Dial("tcp", ss_addr)
	defer func() {
		if ss_conn != nil {
			ss_conn.Close()
		}
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		CliPrintWarning("fwd2Shadowsocks: connecting to shadowsocks: %v", err)
		return
	}
	// iocopy
	go func() {
		_, err = io.Copy(conn, ss_conn)
		if err != nil {
			CliPrintWarning("ss_conn -> kcpconn: %v", err)
			return
		}
	}()
	_, err = io.Copy(ss_conn, conn)
	if err != nil {
		CliPrintWarning("kcpconn -> ss_conn: %v", err)
	}
}
