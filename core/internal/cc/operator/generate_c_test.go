package operator

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
)

func TestGenerateCmdHasCAgentFlags(t *testing.T) {
	cmd := gen_agent_cmd()
	for _, f := range []string{"type", "arch", "cc", "crypto", "gzip", "http", "transport", "dynload", "glibc-version"} {
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
