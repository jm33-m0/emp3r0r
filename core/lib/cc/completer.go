//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

// autocomplete module options
func listValChoices() func(string) []string {
	return func(line string) []string {
		ret := make([]string, 0)
		for _, opt := range CurrentModuleOptions {
			ret = append(ret, opt.Vals...)
		}
		return ret
	}
}

// autocomplete modules names
func listMods() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		for mod := range ModuleHelpers {
			names = append(names, mod)
		}
		return names
	}
}

// autocomplete portfwd session IDs
func listPortMappings() func(string) []string {
	return func(line string) []string {
		ids := make([]string, 0)
		for id := range PortFwds {
			ids = append(ids, id)
		}
		return ids
	}
}

// autocomplete target index and tags
func listTargetIndexTags() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		for t, c := range Targets {
			idx := c.Index
			tag := t.Tag
			names = append(names, strconv.Itoa(idx))
			names = append(names, tag)
		}
		return names
	}
}

// autocomplete option names
func listOptions() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)

		for opt := range CurrentModuleOptions {
			names = append(names, opt)
		}
		return names
	}
}

// remote autocomplete items in $PATH
func listAgentExes(agent *emp3r0r_def.Emp3r0rAgent) []string {
	LogDebug("Listing agent %s's exes in PATH", agent.Tag)
	exes := make([]string, 0)
	if agent == nil {
		LogDebug("No valid target selected so no autocompletion for exes")
		return exes
	}
	for _, exe := range agent.Exes {
		exe = strings.ReplaceAll(exe, "\t", "\\t")
		exe = strings.ReplaceAll(exe, " ", "\\ ")
		exes = append(exes, exe)
	}
	LogDebug("Exes found on agent '%s':\n%v",
		agent.Tag, exes)
	return exes
}

// when a target is selected, update CmdCompls with PATH items
func autoCompleteAgentExes(agent *emp3r0r_def.Emp3r0rAgent) {
	// exes := listAgentExes(agent)
	// temp_CmdCompls := InitCmdCompls
	//
	// is_exe_same_as_cmd := func(exe string) bool {
	// 	for _, cmd := range CLICommands {
	// 		if exe == cmd {
	// 			return true
	// 		}
	// 	}
	// 	return false
	// }
	//
	// for _, exe := range exes {
	// 	if is_exe_same_as_cmd(exe) {
	// 		CliPrintDebug("Exe %s exists in CLI commands, skipping", strconv.Quote(exe))
	// 		continue
	// 	}
	// 	temp_CmdCompls = append(temp_CmdCompls, readline.PcItem(exe))
	// }
	//
	// CmdCompls = temp_CmdCompls
	// CliCompleter.SetChildren(CmdCompls)
}

// remote ls autocomplete items in current directory
func listRemoteDir() func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		cmd := fmt.Sprintf("%s --path .", emp3r0r_def.C2CmdListDir)
		cmd_id := uuid.NewString()
		err := SendCmdToCurrentTarget(cmd, cmd_id)
		if err != nil {
			LogDebug("Cannot list remote directory: %v", err)
			return names
		}
		remote_entries := []string{}
		for i := 0; i < 100; i++ {
			if res, exists := CmdResults[cmd_id]; exists {
				remote_entries = strings.Split(res, "\n")
				CmdResultsMutex.Lock()
				delete(CmdResults, cmd_id)
				CmdResultsMutex.Unlock()
				break
			}
			time.Sleep(100 * time.Millisecond)
			if i == 99 {
				LogDebug("Timeout listing remote directory")
				return names
			}
		}
		if len(remote_entries) == 0 {
			LogDebug("Nothing in remote directory")
			return names
		}
		for _, name := range remote_entries {
			name = strings.ReplaceAll(name, "\t", "\\t")
			name = strings.ReplaceAll(name, " ", "\\ ")
			names = append(names, name)
		}
		return names
	}
}

// Function constructor - constructs new function for listing given directory
// local ls
func listLocalFiles(path string) func(string) []string {
	return func(line string) []string {
		names := make([]string, 0)
		files, _ := os.ReadDir(path)
		for _, f := range files {
			name := strings.ReplaceAll(f.Name(), "\t", "\\t")
			name = strings.ReplaceAll(name, " ", "\\ ")
			names = append(names, name)
		}
		return names
	}
}
