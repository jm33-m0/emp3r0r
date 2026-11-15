package operator

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

func TestDetectLoopCompletionsIncludeInjectAndProcess(t *testing.T) {
	cmd := detectLoopCmd()
	cases := map[string][]string{
		"inject":  {"apc", "ct", "self"},
		"format":  {"exe", "service", "dll"},
		"process": {"dllhost.exe", "notepad.exe"},
	}
	for flag, want := range cases {
		fn, ok := cmd.GetFlagCompletionFunc(flag)
		if !ok {
			t.Fatalf("%s has no completion", flag)
		}
		got, directive := fn(cmd, nil, "")
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Fatalf("%s directive = %v", flag, directive)
		}
		for _, item := range want {
			if !slices.Contains(got, item) {
				t.Fatalf("%s completion = %v, missing %q", flag, got, item)
			}
		}
	}
}
