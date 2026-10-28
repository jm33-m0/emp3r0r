package operator

import (
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
