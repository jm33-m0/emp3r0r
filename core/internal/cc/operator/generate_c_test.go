package operator

import (
	"slices"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
)

func TestGenerateCmdDoesNotOfferCAgent(t *testing.T) {
	cmd := gen_agent_cmd()
	for _, name := range []string{"libc", "crypto", "format", "gzip", "transport", "dynload", "glibc-version", "bof"} {
		if cmd.Flags().Lookup(name) != nil {
			t.Errorf("generate should not define C agent flag --%s", name)
		}
	}
	if slices.Contains(builder.PayloadTypeList, "aquila") || slices.Contains(builder.PayloadTypeList, "c_linux") {
		t.Errorf("C agent must not be a Go generate payload type: %v", builder.PayloadTypeList)
	}
}

func TestGenerateCAgentCmdHasFlags(t *testing.T) {
	cmd := gen_c_cmd()
	for _, name := range []string{"type", "arch", "cc", "cc-http-port", "doh", "crypto", "format", "gzip", "transport", "dynload", "glibc-version", "bof"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("generate_c: missing flag --%s", name)
		}
	}
	if got := cmd.Flags().Lookup("type").DefValue; got != builder.CAgentLibcs[0] {
		t.Errorf("--type default = %q, want libc %q", got, builder.CAgentLibcs[0])
	}
	if got := cmd.Flags().Lookup("arch").DefValue; got != builder.CAgentArches[0] {
		t.Errorf("--arch default = %q, want %q", got, builder.CAgentArches[0])
	}
	if cmd.Flags().Lookup("c2-channel-mode") != nil {
		t.Error("C agent only implements http_poll; it must not expose --c2-channel-mode")
	}
}

func TestCAgentDynloadForLibc(t *testing.T) {
	// An unset --dynload must follow the chosen libc, not the glibc default.
	if got := cAgentDynloadForLibc("musl", "libc_dl", false); got != "public" {
		t.Errorf("musl with default dynload = %q, want public", got)
	}
	// An explicit choice is preserved (and validated later).
	if got := cAgentDynloadForLibc("musl", "public", true); got != "public" {
		t.Errorf("explicit musl dynload changed: %q", got)
	}
	if got := cAgentDynloadForLibc("glibc", "libc_dl", false); got != "libc_dl" {
		t.Errorf("glibc default dynload changed: %q", got)
	}
}
