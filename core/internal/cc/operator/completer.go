package operator

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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
	live.RangeAgents(func(rec *live.AgentRecord) bool {
		names = append(names, strconv.Quote(rec.Agent.Tag)) // escape special characters
		return true
	})
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

// autocomplete items in current remote directory
func listRemoteDir(ctx carapace.Context) carapace.Action {
	activeAgent := agents.MustGetActiveAgent()
	if activeAgent == nil {
		logging.Debugf("No valid target selected so no auto-completion for remote directory")
		return carapace.ActionValues()
	}

	prefix, dirToLis := remoteDirRequest(ctx.Parts)
	listing := listRemoteDirWorker(prefix, dirToLis, activeAgent.Tag)
	return carapace.ActionValues(listing...)
}

// remoteDirRequest derives, from the parts carapace reports for a multi-part
// completion, the exact prefix carapace will prepend to candidates and the
// directory to list on the agent. Splitting a memfs path on "/" yields a first
// component of "memfs:", so memfs paths are rebuilt into canonical
// memfs:/// form (and the typed prefix is kept verbatim, e.g. the two-slash
// "memfs://" is not the three-slash root).
func remoteDirRequest(parts []string) (prefix, dirToLis string) {
	dirToLis = strings.Join(parts, "/")
	if len(parts) > 0 {
		prefix = strings.Join(parts, "/") + "/"
		if parts[0] == "memfs:" {
			rest := strings.TrimLeft(strings.TrimPrefix(prefix, "memfs:"), "/")
			dirToLis = "memfs:///" + strings.TrimSuffix(rest, "/")
		}
	}
	if dirToLis == "" {
		// what if the user wants to complete / ?
		dirToLis = "/"
	}
	return prefix, dirToLis
}

// completionSegment returns the completion candidate for full relative to the
// exact prefix carapace will prepend. Separators immediately following prefix
// are preserved (needed because a typed "memfs://" prefix is not the canonical
// "memfs:///" root) and a trailing separator is kept on intermediate components
// so completion can descend.
func completionSegment(prefix, full string) string {
	rest := strings.TrimPrefix(full, prefix)
	if rest == "" || rest == full {
		return ""
	}
	lead := ""
	for strings.HasPrefix(rest, "/") {
		lead += "/"
		rest = rest[1:]
	}
	if rest == "" {
		return ""
	}
	if i := strings.Index(rest, "/"); i != -1 {
		return lead + rest[:i+1]
	}
	return lead + rest
}

// remoteDirListing decodes a !ls_dir CBOR response ([]util.Dentry) and returns
// completion candidates relative to prefix. Extracted from the worker so the
// decode/segment logic is unit testable without a live agent.
func remoteDirListing(prefix, raw string) []string {
	var dents []util.Dentry
	if err := cbor.Unmarshal([]byte(raw), &dents); err != nil {
		logging.Debugf("listRemoteDirWorker: unmarshal: %v", err)
		return nil
	}

	names := make([]string, 0, len(dents))
	seen := make(map[string]struct{}, len(dents))
	for _, dent := range dents {
		name := dent.Name
		if util.IsMemPath(name) {
			// memfs keys are full paths; reduce to the next segment below the
			// typed prefix so carapace does not concatenate them twice.
			name = completionSegment(prefix, name)
		} else if dent.Ftype == "dir" {
			// Trailing slash lets completion descend into the directory.
			name += "/"
		}
		if name == "" {
			continue
		}
		// Filenames are agent-controlled: strip terminal escapes/control bytes
		// before they are rendered as completion candidates.
		name = util.SanitizeText(name)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		name = strings.ReplaceAll(name, "\t", "\\t")
		name = strings.ReplaceAll(name, " ", "\\ ")
		names = append(names, name)
	}
	return names
}

func listRemoteDirWorker(prefix, pathToList string, agentTag string) (names []string) {
	names = make([]string, 0) // listing to return
	cmd := fmt.Sprintf("%s --path %s", def.C2CmdListDir, strconv.Quote(pathToList))
	job_id := uuid.NewString()
	// Register a ready channel before sending the command so we don't miss the signal.
	resultReady := make(chan struct{}, 1)
	live.CmdResultsReady.Store(job_id, resultReady)

	err := controllers.ExecuteCommand(cmd, job_id, agentTag)
	if err != nil {
		live.CmdResultsReady.Delete(job_id) // clean up if we never send
		logging.Debugf("Cannot list remote directory: %v", err)
		return names
	}
	listingCtx, listingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listingCancel()
	select {
	case <-resultReady:
		if res, ok := live.CmdResultString(job_id); ok {
			names = remoteDirListing(prefix, res)
			live.CmdResults.Delete(job_id)
		}
	case <-listingCtx.Done():
		live.CmdResultsReady.Delete(job_id) // timed out, clean up orphaned channel
		logging.Debugf("listRemoteDirWorker: timeout waiting for result")
	}
	if len(names) == 0 {
		logging.Debugf("Nothing in remote directory")
	}
	return names
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
		if res, ok := live.CmdResultString(job_id); ok {
			var entries []def.TokenEntry
			if err := cbor.Unmarshal([]byte(res), &entries); err != nil {
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
