//go:build linux

package operator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestParseTransportOptions(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().StringSlice("transport-option", nil, "")
	if err := cmd.Flags().Set("transport-option", "socks5=127.0.0.1:9050"); err != nil {
		t.Fatalf("set option: %v", err)
	}
	if err := cmd.Flags().Set("transport-option", "folder=abc=def"); err != nil {
		t.Fatalf("set option: %v", err)
	}

	options, err := parseTransportOptions(cmd)
	if err != nil {
		t.Fatalf("parseTransportOptions: %v", err)
	}
	if options["socks5"] != "127.0.0.1:9050" {
		t.Fatalf("socks5 = %q", options["socks5"])
	}
	if options["folder"] != "abc=def" {
		t.Fatalf("folder = %q", options["folder"])
	}

	bad := &cobra.Command{Use: "bad"}
	bad.Flags().StringSlice("transport-option", nil, "")
	if err := bad.Flags().Set("transport-option", "missing-value"); err != nil {
		t.Fatalf("set bad option: %v", err)
	}
	if _, err := parseTransportOptions(bad); err == nil {
		t.Fatal("parseTransportOptions accepted a value without '='")
	}
}

func TestGenerateAgentTagCompletion(t *testing.T) {
	cmd := gen_agent_cmd()
	complete, ok := cmd.GetFlagCompletionFunc("agent-tags")
	if !ok {
		t.Fatal("generate has no agent-tags completion")
	}
	values, directive := complete(cmd, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("completion directive = %v", directive)
	}
	want := map[string]bool{"with_mesh": true, "with_kcp": true, "with_quic": true}
	for _, value := range values {
		delete(want, value)
	}
	if len(want) != 0 {
		t.Fatalf("completion is missing %v (got %v)", want, values)
	}
	if cmd.Flags().Lookup("list-agent-tags") == nil {
		t.Fatal("generate has no list-agent-tags flag")
	}
}

func TestGenerateListAgentTagsDoesNotRequireCC(t *testing.T) {
	cmd := gen_agent_cmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--list-agent-tags"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("list-agent-tags failed: %v", err)
	}
	if !strings.Contains(out.String(), "with_mesh") {
		t.Fatalf("tag reference missing from output: %q", out.String())
	}
}
