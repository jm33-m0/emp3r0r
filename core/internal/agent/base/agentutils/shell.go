package agentutils

import (
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// shellCandidates are the shells tried, in order, for in-memory script
// execution. bash is preferred because the module scripts assume bash builtins.
var shellCandidates = []string{"/bin/bash", "/bin/sh"}

var (
	shellOnce sync.Once
	shellPath string
)

// DefaultShell returns the path of the shell used to run scripts on this host,
// or "" when no supported shell is installed. The lookup touches the filesystem
// and is cached with sync.Once: ExecuteShell runs on every module invocation,
// and the result cannot change while the agent is alive.
func DefaultShell() string {
	shellOnce.Do(func() {
		for _, candidate := range shellCandidates {
			if util.IsFileExist(candidate) {
				shellPath = candidate
				return
			}
		}
	})
	return shellPath
}
