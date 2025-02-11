//go:build linux
// +build linux

package cc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/rsteube/carapace"
)

// autocomplete module options
func listValChoices(ctx carapace.Context) carapace.Action {
	ret := make([]string, 0)
	argc := len(ctx.Args)
	prev_word := ctx.Args[argc-1]
	for _, opt := range AvailableModuleOptions {
		if prev_word == opt.Name {
			ret = append(ret, opt.Vals...)
			break
		}
	}
	return carapace.ActionValues(ret...)
}

// autocomplete modules names
func listMods(ctx carapace.Context) carapace.Action {
	names := make([]string, 0)
	for mod := range ModuleHelpers {
		names = append(names, mod)
	}
	return carapace.ActionValues(names...)
}

// autocomplete portfwd session IDs
func listPortMappings(ctx carapace.Context) carapace.Action {
	ids := make([]string, 0)
	for id := range PortFwds {
		ids = append(ids, id)
	}
	return carapace.ActionValues(ids...)
}

// autocomplete target index and tags
func listTargetIndexTags(ctx carapace.Context) carapace.Action {
	names := make([]string, 0)
	for t, c := range Targets {
		idx := c.Index
		tag := t.Tag
		tag = strconv.Quote(tag) // escape special characters
		names = append(names, strconv.Itoa(idx))
		names = append(names, tag)
	}
	return carapace.ActionValues(names...)
}

// autocomplete option names
func listOptions(ctx carapace.Context) carapace.Action {
	names := make([]string, 0)

	for opt := range AvailableModuleOptions {
		names = append(names, opt)
	}
	return carapace.ActionValues(names...)
}

// remote autocomplete items in $PATH
func listAgentExes(ctx carapace.Context) carapace.Action {
	agent := ValidateActiveTarget()
	if agent == nil {
		LogDebug("No valid target selected so no autocompletion for exes")
		return carapace.ActionValues()
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
	return carapace.ActionValues(exes...)
}

// Cache for remote directory listing
// cwd: listing
type RemoteDirListingCache struct {
	CWD     string
	Listing []string
	Ctx     context.Context
	Cancel  context.CancelFunc
}

var (
	RemoteDirListing      = make(map[string]*RemoteDirListingCache)
	RemoteDirListingMutex = new(sync.RWMutex)
)

// autocomplete items in current remote directory
func listRemoteDir(ctx carapace.Context) carapace.Action {
	activeAgent := ValidateActiveTarget()
	if activeAgent == nil {
		LogDebug("No valid target selected so no autocompletion for remote directory")
		return carapace.ActionValues()
	}

	// if we have the listing in cache, return it
	// otherwise caparace will run it too many times to slow down the console
	RemoteDirListingMutex.RLock()
	if cache, exists := RemoteDirListing[activeAgent.CWD]; exists {
		RemoteDirListingMutex.RUnlock()
		LogDebug("Listing remote directory %s from cache", activeAgent.CWD)
		return carapace.ActionValues(cache.Listing...)
	}
	RemoteDirListingMutex.RUnlock()

	names := make([]string, 0) // listing to return
	cmd := fmt.Sprintf("%s --path %s", emp3r0r_def.C2CmdListDir, activeAgent.CWD)
	cmd_id := uuid.NewString()
	err := SendCmdToCurrentTarget(cmd, cmd_id)
	if err != nil {
		LogDebug("Cannot list remote directory: %v", err)
		return carapace.ActionValues()
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
			return carapace.ActionValues()
		}
	}
	if len(remote_entries) == 0 {
		LogDebug("Nothing in remote directory")
		return carapace.ActionValues()
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
	cache := &RemoteDirListingCache{
		CWD:     remote_entries[0],
		Listing: names,
	}
	cache.Ctx, cache.Cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	RemoteDirListing[remote_entries[0]] = cache

	return carapace.ActionValues(names...)
}
