package tun

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

// controls ss server
var SSServerConfig struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool // coalesce writing first few packets
}

const SSAEADCipher = "AEAD_CHACHA20_POLY1305"

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

// SSConfig start ss server/client with this config
type SSConfig struct {
	ServerAddr     string // ss server address
	LocalSocksAddr string // ss client local socks address, leave empty to disable
	Cipher         string // ss cipher, AEAD_CHACHA20_POLY1305
	Password       string // ss password
	IsServer       bool   // is ss server or client or tunnel
	Verbose        bool   // verbose logging

	// Tunnels: eg. :8053=8.8.8.8:53,:8054=8.8.4.4:53
	// (client-only) tunnel (local_addr1=remote_addr1,local_addr2=remote_addr2,...)
	TCPTun string
	UDPTun string

	// used as switch
	Ctx    context.Context
	Cancel context.CancelFunc
}

// Start shadowsocks server / client
// server_addr: addr of shadowsocks server
// socks_addr: addr of the local socks5 proxy started by shadowsocks client
func SSMain(ss_config *SSConfig) (err error) {
	SSServerConfig.Verbose = ss_config.Verbose // verbose logging

	// ss:// URL as server address
	if strings.HasPrefix(ss_config.ServerAddr, "ss://") {
		ss_config.ServerAddr, ss_config.Cipher, ss_config.Password, err = ParseSSURL(ss_config.ServerAddr)
		if err != nil {
			return
		}
	}

	var key []byte // leave empty to use password
	// Derive key from password if given key is empty.
	ciph, err := core.PickCipher(ss_config.Cipher, key, ss_config.Password)
	if err != nil {
		return
	}

	// Start shadowsocks server / client / TCP tunnel / UDP tunnel
	if ss_config.IsServer {
		// go-shadowsocks2 -s 'ss://AEAD_CHACHA20_POLY1305:your-password@:8488' -verbose
		go tcpRemote(ss_config.ServerAddr, ciph.StreamConn, ss_config.Ctx, ss_config.Cancel)
	} else if ss_config.LocalSocksAddr != "" {
		// go-shadowsocks2 -c 'ss://AEAD_CHACHA20_POLY1305:your-password@[server_address]:8488'
		// -verbose -socks :1080 -u -udptun :8053=8.8.8.8:53,:8054=8.8.4.4:53
		//                          -tcptun :8053=8.8.8.8:53,:8054=8.8.4.4:53
		go socksLocal(ss_config.LocalSocksAddr, ss_config.ServerAddr,
			ciph.StreamConn,
			ss_config.Ctx, ss_config.Cancel)
	} else if ss_config.TCPTun != "" {
		// support multiple TCP tunnels
		for _, tun := range strings.Split(ss_config.TCPTun, ",") {
			p := strings.Split(tun, "=")
			server := ss_config.ServerAddr
			go tcpTun(p[0], server, p[1], ciph.StreamConn, ss_config.Ctx, ss_config.Cancel)
		}
	} else if ss_config.UDPTun != "" {
		return fmt.Errorf("UDP tunnel not implemented yet")
	} else {
		err = fmt.Errorf("invalid ss config")
	}

	return
}

// ParseSSURL parse ss:// URL, eg. ss://AEAD_CHACHA20_POLY1305:your-password@[server_address]:8488
func ParseSSURL(s string) (addr, cipher, password string, err error) {
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
