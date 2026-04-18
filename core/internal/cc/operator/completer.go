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
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// autocomplete module options
func listValChoices(ctx carapace.Context) carapace.Action {
	if live.ActiveModule == nil {
		return carapace.ActionValues()
	}
	ret := make([]string, 0)
	argc := len(ctx.Args)
	if argc == 0 {
		return carapace.ActionValues()
	}
	prev_word := ctx.Args[argc-1]
	prev_word = strings.TrimPrefix(prev_word, "--")
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
	def.Modules.Range(func(key, value any) bool {
		names = append(names, key.(string))
		return true
	})
	return carapace.ActionValues(names...)
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

var RemoteDirListing sync.Map

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
	RemoteDirListing.Store(cache.CWD, cache)

	return carapace.ActionValues(listing...)
}

func listRemoteDirWorker(path_to_list, agent_tag string) (cwd string, names []string) {
	names = make([]string, 0) // listing to return
	cmd := fmt.Sprintf("%s --path %s", def.C2CmdListDir, strconv.Quote(path_to_list))
	job_id := uuid.NewString()
	// Register a ready channel before sending the command so we don't miss the signal.
	resultReady := make(chan struct{}, 1)
	live.CmdResultsReady.Store(job_id, resultReady)

	err := controllers.ExecuteCommand(cmd, job_id, agent_tag)
	if err != nil {
		live.CmdResultsReady.Delete(job_id) // clean up if we never send
		logging.Debugf("Cannot list remote directory: %v", err)
		return
	}
	remote_entries := []string{}
	listingCtx, listingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listingCancel()
	select {
	case <-resultReady:
		if res, exists := live.CmdResults.Load(job_id); exists {
			safeListing := util.SanitizeText(res.(string))
			remote_entries = strings.Split(safeListing, "\n")
			live.CmdResults.Delete(job_id)
		}
	case <-listingCtx.Done():
		live.CmdResultsReady.Delete(job_id) // timed out, clean up orphaned channel
		logging.Debugf("listRemoteDirWorker: timeout waiting for result")
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
