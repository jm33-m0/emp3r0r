package operator

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/carapace-sh/carapace"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// autocomplete module options
func listValChoices(ctx carapace.Context) carapace.Action {
	ret := make([]string, 0)
	argc := len(ctx.Args)
	prev_word := ctx.Args[argc-1]
	for _, opt := range live.ActiveModule.Options {
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
	for mod := range def.Modules {
		names = append(names, mod)
	}
	return carapace.ActionValues(names...)
}

// autocomplete portfwd session IDs
func listPortMappings(ctx carapace.Context) carapace.Action {
	ids := make([]string, 0)
	for id := range network.PortFwds {
		ids = append(ids, id)
	}
	return carapace.ActionValues(ids...)
}

// autocomplete agent tags
func listAgents(ctx carapace.Context) carapace.Action {
	names := make([]string, 0)
	for _, t := range live.AgentList {
		tag := t.Tag
		tag = strconv.Quote(tag) // escape special characters
		names = append(names, tag)
	}
	return carapace.ActionValues(names...)
}

// autocomplete option names
func listOptions(ctx carapace.Context) carapace.Action {
	names := make([]string, 0)

	for opt := range live.ActiveModule.Options {
		names = append(names, opt)
	}
	return carapace.ActionValues(names...)
}

// remote autocomplete items in $PATH
func listAgentExes(ctx carapace.Context) carapace.Action {
	agent := agents.MustGetActiveAgent()
	if agent == nil {
		logging.Debugf("No valid target selected so no autocompletion for exes")
		return carapace.ActionValues()
	}
	logging.Debugf("Listing agent %s's exes in PATH", agent.Tag)
	exes := make([]string, 0)
	for _, exe := range agent.Exes {
		exe = strings.ReplaceAll(exe, "\t", "\\t")
		exe = strings.ReplaceAll(exe, " ", "\\ ")
		exes = append(exes, exe)
	}
	logging.Debugf("Exes found on agent '%s':\n%v",
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
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Debugf("No valid target selected so no auto-completion for remote directory")
		return carapace.ActionValues()
	}

	// what dir to list
	dir_to_list := strings.Join(ctx.Parts, "/")
	if dir_to_list == "" {
		// what if the user wants to complete / ?
		dir_to_list = "/"
	}

	cwd, listing := listRemoteDirWorker(dir_to_list, activeAgent.Tag)
	cache := &RemoteDirListingCache{
		CWD:     cwd,
		Listing: listing,
	}
	cache.Ctx, cache.Cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	RemoteDirListing[cache.CWD] = cache

	return carapace.ActionValues(listing...)
}

func listRemoteDirWorker(path_to_list, agent_tag string) (cwd string, names []string) {
	names = make([]string, 0) // listing to return
	cmd := fmt.Sprintf("%s --path %s", def.C2CmdListDir, path_to_list)
	cmd_id := uuid.NewString()
	err := operatorSendCommand2Agent(cmd, cmd_id, agent_tag)
	if err != nil {
		logging.Debugf("Cannot list remote directory: %v", err)
		return
	}
	remote_entries := []string{}
	listingCtx, listingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listingCancel()
	for listingCtx.Err() == nil {
		if res, exists := live.CmdResults.Load(cmd_id); exists {
			remote_entries = strings.Split(res.(string), "\n")
			live.CmdResults.Delete(cmd_id)
			listingCancel()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(remote_entries) == 0 {
		logging.Debugf("Nothing in remote directory")
		return
	}
	cwd = remote_entries[0]
	for n, name := range remote_entries {
		if n == 0 {
			continue // this is the cwd
		}
		name = strings.ReplaceAll(name, "\t", "\\t")
		name = strings.ReplaceAll(name, " ", "\\ ")
		names = append(names, name)
	}
	return
}
