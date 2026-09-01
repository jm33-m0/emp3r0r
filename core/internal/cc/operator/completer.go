package operator

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/carapace-sh/carapace"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

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

	// Handle memfs paths: if user typed mem:// or mem:///, we need to preserve that
	// ctx.Parts might be ["mem:", ""] for "mem:/" or ["mem:", "", ""] for "mem://"
	// We want to reconstruct the proper mem:// prefix
	if len(ctx.Parts) > 0 && strings.HasPrefix(ctx.Parts[0], "mem") {
		// Reconstruct as mem:// + rest of path
		restParts := ctx.Parts[1:]
		if len(restParts) == 0 || (len(restParts) == 1 && restParts[0] == "") {
			dir_to_list = "mem://"
		} else {
			// Remove empty parts and rejoin
			var nonEmpty []string
			for _, part := range restParts {
				if part != "" {
					nonEmpty = append(nonEmpty, part)
				}
			}
			if len(nonEmpty) == 0 {
				dir_to_list = "mem://"
			} else {
				dir_to_list = "mem:///" + strings.Join(nonEmpty, "/")
			}
		}
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
		return cwd, names
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
		return cwd, names
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
	return cwd, names
}

// autocomplete cached impersonation tokens from target agent
// Returns only the SID portion (quoted), e.g. "S-1-5-21-..."
func listTokens(ctx carapace.Context) carapace.Action {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Debugf("No valid target selected so no auto-completion for tokens")
		return carapace.ActionValues()
	}

	tokens := listTokensWorker(activeAgent.Tag)
	return carapace.ActionValues(tokens...)
}

// autocomplete make_token netlogon session names from target agent
// Returns only the session name (quoted), e.g. "DOMAIN\\user"
func listSessions(ctx carapace.Context) carapace.Action {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Debugf("No valid target selected so no auto-completion for sessions")
		return carapace.ActionValues()
	}

	sessions := listSessionsWorker(activeAgent.Tag)
	return carapace.ActionValues(sessions...)
}

func listTokensWorker(agent_tag string) (tokens []string) {
	tokens = make([]string, 0)
	// --quiet: the data still comes back (read from CmdResults below) but the
	// CC console skips rendering it (see controllers.ProcessAgentResponse).
	cmd := def.C2CmdListTokens + " --quiet"
	job_id := uuid.NewString()
	resultReady := make(chan struct{}, 1)
	live.CmdResultsReady.Store(job_id, resultReady)

	err := controllers.ExecuteCommand(cmd, job_id, agent_tag)
	if err != nil {
		live.CmdResultsReady.Delete(job_id)
		logging.Debugf("Cannot list tokens: %v", err)
		return tokens
	}
	listingCtx, listingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listingCancel()
	select {
	case <-resultReady:
		if res, exists := live.CmdResults.Load(job_id); exists {
			var entries []def.TokenEntry
			if err := cbor.Unmarshal([]byte(res.(string)), &entries); err != nil {
				logging.Debugf("listTokensWorker: unmarshal: %v", err)
			} else {
				for _, e := range entries {
					tokens = append(tokens, strconv.Quote(e.Key))
				}
			}
			live.CmdResults.Delete(job_id)
		}
	case <-listingCtx.Done():
		live.CmdResultsReady.Delete(job_id)
		logging.Debugf("listTokensWorker: timeout waiting for result")
	}
	return tokens
}

func listSessionsWorker(agent_tag string) (sessions []string) {
	sessions = make([]string, 0)
	cmd := def.C2CmdListSessions + " --quiet"
	job_id := uuid.NewString()
	resultReady := make(chan struct{}, 1)
	live.CmdResultsReady.Store(job_id, resultReady)

	err := controllers.ExecuteCommand(cmd, job_id, agent_tag)
	if err != nil {
		live.CmdResultsReady.Delete(job_id)
		logging.Debugf("Cannot list sessions: %v", err)
		return sessions
	}
	listingCtx, listingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listingCancel()
	select {
	case <-resultReady:
		if res, exists := live.CmdResults.Load(job_id); exists {
			var entries []def.SessionEntry
			if err := cbor.Unmarshal([]byte(res.(string)), &entries); err != nil {
				logging.Debugf("listSessionsWorker: unmarshal: %v", err)
			} else {
				for _, e := range entries {
					sessions = append(sessions, strconv.Quote(e.Name))
				}
			}
			live.CmdResults.Delete(job_id)
		}
	case <-listingCtx.Done():
		live.CmdResultsReady.Delete(job_id)
		logging.Debugf("listSessionsWorker: timeout waiting for result")
	}
	return sessions
}
