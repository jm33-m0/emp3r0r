package modules

// socks5_test.go — the operator-side half of the C-agent SOCKS5 pivot:
// `socks_start` hosts the relay BOF and its loader for the agent, and the agent
// runs that BOF when the C2's listener sends !proxy_start. A Go agent has the
// relay built in, so nothing is hosted for it.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// socks5HostedModule registers a module whose payload exists in a temp dir, so
// the hosting path builds nothing and exercises compression and registration.
func socks5HostedModule(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	payload := name + ".bin"
	if err := os.WriteFile(filepath.Join(dir, payload), []byte("payload-"+name), 0o600); err != nil {
		t.Fatalf("write %s: %v", payload, err)
	}
	def.Modules.Store(name, &def.ModuleConfig{
		Name:        name,
		Platform:    "Linux",
		Path:        dir,
		AgentConfig: def.AgentModuleConfig{Type: "coff", Files: []string{payload}},
	})
}

// TestHostSocks5RelayForCAgent checks that the operator hosts exactly the two
// archives a C agent fetches by name when it serves a pivot connection.
func TestHostSocks5RelayForCAgent(t *testing.T) {
	stubRemoteDownloads(t)
	origRoot := paths.WWWRoot
	paths.WWWRoot = t.TempDir()
	t.Cleanup(func() {
		paths.WWWRoot = origRoot
		for _, name := range []string{"socks5.amd64.gz", "coffloader_linux.amd64.gz"} {
			network.WWWDownloads.Delete(network.LocalWWWDownloadKey(name))
		}
	})
	for _, name := range []string{ModSocks5, "coffloader_linux"} {
		name := name
		orig, had := def.GetModule(name)
		t.Cleanup(func() {
			if had {
				def.Modules.Store(name, orig)
			} else {
				def.Modules.Delete(name)
			}
		})
		socks5HostedModule(t, name)
	}

	agent := &def.Emp3r0rAgent{
		UUID: "33333333-3333-4333-8333-333333333333", Tag: "socks5-c",
		GOOS: "linux", GOArch: "amd64", AgentImpl: "c",
	}
	if err := HostSocks5Relay(agent); err != nil {
		t.Fatalf("HostSocks5Relay: %v", err)
	}
	for _, name := range []string{"socks5.amd64.gz", "coffloader_linux.amd64.gz"} {
		val, ok := network.WWWDownloads.Load(network.LocalWWWDownloadKey(name))
		if !ok {
			t.Fatalf("%s was not registered for the agent", name)
		}
		if got := val.(*network.WWWDownload).AgentUUID; got != agent.UUID {
			t.Fatalf("%s is registered for %q, want %q", name, got, agent.UUID)
		}
		if _, err := os.Stat(filepath.Join(paths.WWWRoot, name)); err != nil {
			t.Fatalf("%s was not written to the WWW root: %v", name, err)
		}
	}
}

// TestHostSocks5RelayForGoAgent checks that a Go agent, which has the relay
// built in, gets nothing hosted.
func TestHostSocks5RelayForGoAgent(t *testing.T) {
	stubRemoteDownloads(t)
	origRoot := paths.WWWRoot
	paths.WWWRoot = t.TempDir()
	t.Cleanup(func() { paths.WWWRoot = origRoot })
	// Drop any registration a previous test left behind: this test asserts
	// that nothing is hosted.
	for _, name := range []string{"socks5.amd64.gz", "coffloader_linux.amd64.gz"} {
		network.WWWDownloads.Delete(network.LocalWWWDownloadKey(name))
	}

	agent := &def.Emp3r0rAgent{GOOS: "linux", GOArch: "amd64", AgentImpl: "go"}
	if err := HostSocks5Relay(agent); err != nil {
		t.Fatalf("HostSocks5Relay: %v", err)
	}
	for _, name := range []string{"socks5.amd64.gz", "coffloader_linux.amd64.gz"} {
		if _, ok := network.WWWDownloads.Load(network.LocalWWWDownloadKey(name)); ok {
			t.Fatalf("%s was hosted for a Go agent", name)
		}
	}
}
