//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

// autocomplete module options
func listValChoices() []string {
	ret := make([]string, 0)
	for _, opt := range AvailableModuleOptions {
		ret = append(ret, opt.Vals...)
	}
	return ret
}

// autocomplete modules names
func listMods() []string {
	names := make([]string, 0)
	for mod := range ModuleHelpers {
		names = append(names, mod)
	}
	return names
}

// autocomplete portfwd session IDs
func listPortMappings() []string {
	ids := make([]string, 0)
	for id := range PortFwds {
		ids = append(ids, id)
	}
	return ids
}

// autocomplete target index and tags
func listTargetIndexTags() []string {
	names := make([]string, 0)
	for t, c := range Targets {
		idx := c.Index
		tag := t.Tag
		tag = strconv.Quote(tag) // escape special characters
		names = append(names, strconv.Itoa(idx))
		names = append(names, tag)
	}
	return names
}

// autocomplete option names
func listOptions() []string {
	names := make([]string, 0)

	for opt := range AvailableModuleOptions {
		names = append(names, opt)
	}
	return names
}

// remote autocomplete items in $PATH
func listAgentExes() []string {
	agent := ValidateActiveTarget()
	if agent == nil {
		LogDebug("No valid target selected so no autocompletion for exes")
		return []string{}
	}
	LogDebug("Listing agent %s's exes in PATH", agent.Tag)
	exes := make([]string, 0)
	for _, exe := range agent.Exes {
		exe = strings.ReplaceAll(exe, "\t", "\\t")
		exe = strings.ReplaceAll(exe, " ", "\\ ")
		exes = append(exes, exe)
	}
	LogDebug("Exes found on agent '%s':\n%v",
		agent.Tag, exes)
	return exes
}

// Cache for remote directory listing
// cwd: listing
var (
	RemoteDirListing      = make(map[string][]string)
	RemoteDirListingMutex = new(sync.RWMutex)
)

// autocomplete items in current remote directory
func listRemoteDir() []string {
	activeAgent := ValidateActiveTarget()
	if activeAgent == nil {
		LogDebug("No valid target selected so no autocompletion for remote directory")
		return []string{}
	}

	// if we have the listing in cache, return it
	// otherwise caparace will run it too many times to slow down the console
	RemoteDirListingMutex.RLock()
	if names, exists := RemoteDirListing[activeAgent.CWD]; exists {
		RemoteDirListingMutex.RUnlock()
		LogDebug("Listing remote directory %s from cache", activeAgent.CWD)
		return names
	}
	RemoteDirListingMutex.RUnlock()

	names := make([]string, 0) // listing to return
	cmd := fmt.Sprintf("%s --path %s", emp3r0r_def.C2CmdListDir, activeAgent.CWD)
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
	for n, name := range remote_entries {
		if n == 0 {
			continue // this is the cwd
		}
		name = strings.ReplaceAll(name, "\t", "\\t")
		name = strings.ReplaceAll(name, " ", "\\ ")
		names = append(names, name)
	}
	RemoteDirListingMutex.Lock()
	defer RemoteDirListingMutex.Unlock()
	RemoteDirListing[remote_entries[0]] = names
	return names
}

// Function constructor - constructs new function for listing given directory
// local ls
func listLocalFiles(path string) []string {
	names := make([]string, 0)
	files, _ := os.ReadDir(path)
	for _, f := range files {
		name := strings.ReplaceAll(f.Name(), "\t", "\\t")
		name = strings.ReplaceAll(name, " ", "\\ ")
		names = append(names, name)
	}
	return names
}
