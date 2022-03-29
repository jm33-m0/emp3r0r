package ss

import (
	"net/url"
	"strings"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

// controls logging behavior
var config struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool // coalesce writing first few packets
}

const AEADCipher = "AEAD_CHACHA20_POLY1305"

// shadowsocks config options
var flags struct {
	Client     string // client connect address or url
	Server     string // server listen address or url
	Cipher     string // AEAD_CHACHA20_POLY1305
	Key        string // base64url-encoded key (derive from password if empty)
	Password   string // shadowsocks password
	Keygen     int    // generate a base64url-encoded random key of given length in byte
	Socks      string // (client-only) SOCKS listen address
	RedirTCP   string // (client-only) redirect TCP from this address
	RedirTCP6  string // (client-only) redirect TCP IPv6 from this address
	TCPTun     string // (client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)
	UDPTun     string // (client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)
	UDPSocks   bool   // (client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)
	UDP        bool   // (server-only) enable UDP support
	TCP        bool   // (server-only) enable TCP support
	Plugin     string // Enable SIP003 plugin. (e.g., v2ray-plugin)
	PluginOpts string // Set SIP003 plugin options. (e.g., "server;tls;host=mydomain.me")
}

// Start shadowsocks server / client
// server_addr: addr of shadowsocks server
// socks_addr: addr of the local socks5 proxy started by shadowsocks client
func SSMain(server_addr, socks_addr,
	cipher, password string,
	isServer, verbose bool) (err error) {

	config.Verbose = verbose // verbose logging

	// ss:// URL as server address
	if strings.HasPrefix(server_addr, "ss://") {
		server_addr, cipher, password, err = parseURL(server_addr)
		if err != nil {
			return
		}
	}

	var key []byte // leave empty to use password
	// Derive key from password if given key is empty.
	ciph, err := core.PickCipher(cipher, key, password)
	if err != nil {
		return
	}
	if isServer {
		go tcpRemote(server_addr, ciph.StreamConn)
	} else {
		go socksLocal(socks_addr, server_addr, ciph.StreamConn)
	}

	return
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
