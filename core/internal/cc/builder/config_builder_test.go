package builder

import (
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestC2AddressHelpers(t *testing.T) {
	if got := c2AddressHost("https://front.example.com:8443"); got != "front.example.com" {
		t.Fatalf("c2AddressHost(full URL) = %q", got)
	}
	if got := c2AddressHost("c2.example.com"); got != "c2.example.com" {
		t.Fatalf("c2AddressHost(host) = %q", got)
	}
	if got := c2BaseURL("https://front.example.com", "http", "8080"); got != "https://front.example.com" {
		t.Fatalf("c2BaseURL(explicit) = %q", got)
	}
	if got := c2BaseURL("c2.example.com", "http", "8080"); got != "http://c2.example.com:8080" {
		t.Fatalf("c2BaseURL(host) = %q", got)
	}
}

func TestMakeConfigCustomTransport(t *testing.T) {
	oldWorkspace, oldConfigFile, oldRuntime := live.EmpWorkSpace, live.EmpConfigFile, live.RuntimeConfig
	defer func() {
		live.EmpWorkSpace, live.EmpConfigFile, live.RuntimeConfig = oldWorkspace, oldConfigFile, oldRuntime
	}()

	workspace := t.TempDir()
	live.EmpWorkSpace = workspace
	live.EmpConfigFile = filepath.Join(workspace, "emp3r0r.json")
	live.RuntimeConfig = &def.Config{
		CCAddress:     "ignored.example",
		CCH2Port:      "8443",
		CCHTTPPort:    "8080",
		C2Routes:      def.C2Routing{Checkin: "c", Msg: "m", FTP: "f", WWW: "w", Proxy: "p"},
		C2ChannelMode: "http_poll",
	}

	mode := "tor"
	address := "abcdefghijklmnop.onion:80"
	if err := MakeConfig(AgentConfig{
		CCAddress:            &address,
		C2ChannelMode:        &mode,
		AllowCustomTransport: true,
		TransportOptions:     map[string]string{"socks5": "127.0.0.1:9050"},
	}); err != nil {
		t.Fatalf("MakeConfig: %v", err)
	}

	if live.RuntimeConfig.C2ChannelMode != mode {
		t.Fatalf("mode = %q", live.RuntimeConfig.C2ChannelMode)
	}
	if live.RuntimeConfig.CCAddress != address {
		t.Fatalf("address = %q", live.RuntimeConfig.CCAddress)
	}
	if live.RuntimeConfig.PreflightEnabled {
		t.Fatal("HTTP preflight is enabled for a custom transport")
	}
	if got := live.RuntimeConfig.TransportOptions["socks5"]; got != "127.0.0.1:9050" {
		t.Fatalf("transport option = %q", got)
	}
}
