package agentutils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// InitializePath augments PATH with the platform's common tool directories and
// removes duplicates, so modules and spawned tools resolve even when the loader
// handed us a minimal environment. Existing entries are kept (normalized in
// place) and take precedence over the appended defaults.
func InitializePath() {
	var common []string
	if runtime.GOOS == "windows" {
		common = []string{
			`c:\windows\system32`,
			`c:\windows`,
			`c:\windows\system32\wbem`,
			`c:\windows\system32\windowspowershell\v1.0`,
			`c:\windows\system32\openssh`,
		}
	} else {
		common = []string{
			"/bin",
			"/sbin",
			"/usr/bin",
			"/usr/games",
			"/usr/sbin",
			"/usr/local/bin",
			"/usr/local/sbin",
			"/snap/bin",
		}
	}

	entries := splitPath(os.Getenv("PATH"))
	if runtime.GOOS == "windows" {
		// Windows PATH lookups are case-insensitive, so canonicalize the case
		// to make duplicate detection reliable.
		for i, p := range entries {
			entries[i] = strings.ToLower(p)
		}
	}
	// Existing entries win over the defaults by appearing first.
	entries = util.RemoveDupsFromArray(append(entries, common...))

	separator := string(os.PathListSeparator)
	pathStr := strings.Join(entries, separator)
	if runtime.GOOS == "windows" {
		// A trailing separator is conventional on Windows.
		pathStr += separator
	}
	if err := os.Setenv("PATH", pathStr); err != nil {
		logging.Warningf("cannot update PATH: %v", err)
		return
	}
	logging.Infof("PATH=%s", pathStr)
}

// splitPath splits a PATH value into cleaned, non-empty entries. Cleaning keeps
// absolute paths absolute; the previous implementation trimmed the leading
// separator, which turned "/usr/bin" into the relative "usr/bin".
func splitPath(value string) []string {
	var out []string
	for _, p := range strings.Split(value, string(os.PathListSeparator)) {
		p = strings.TrimSpace(p)
		if p == "" {
			// An empty PATH entry means "current directory" and is both a
			// hazard and unhelpful for deduplication, so drop it.
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}
