package operator

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
)

func TestGenerateCmdHasCAgentFlags(t *testing.T) {
	cmd := gen_agent_cmd()
	for _, f := range []string{"type", "arch", "cc", "crypto", "libc", "format", "gzip", "http", "transport", "dynload", "glibc-version"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("generate: missing flag --%s", f)
		}
	}

	found := false
	for _, p := range builder.PayloadTypeList {
		if p == builder.PayloadTypeAquila {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("%s is not offered in builder.PayloadTypeList", builder.PayloadTypeAquila)
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
