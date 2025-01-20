package emp3r0r_def

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

// ModOption represents module options
type ModOption struct {
	OptName string   `json:"opt_name"` // option name
	OptDesc string   `json:"opt_desc"` // option description
	OptVal  string   `json:"opt_val"`  // option value
	OptVals []string `json:"opt_vals"` // option value candidates
}

// ModOptions represents multiple module options
type ModOptions map[string]*ModOption

// ModConfig stores module config data
type ModConfig struct {
	Name          string     `json:"name"`        // Display as this name
	Exec          string     `json:"exec"`        // Run this executable file
	InMemory      bool       `json:"in_memory"`   // run this module in memory (for now ps1 is supported)
	Type          string     `json:"type"`        // "go", "python", "powershell", "bash", "exe", "elf", "dll", "so"
	Platform      string     `json:"platform"`    // targeting which OS? Linux/Windows
	IsInteractive bool       `json:"interactive"` // whether run as a shell or not, eg. python, bettercap
	Author        string     `json:"author"`      // by whom
	Date          string     `json:"date"`        // when did you write it
	Comment       string     `json:"comment"`     // describe your module in one line
	Path          string     `json:"path"`        // where is this module stored? eg. ~/.emp3r0r/modules
	Options       ModOptions `json:"options"`     // module options
}

// Module help info and options
var Modules = map[string]*ModConfig{}
