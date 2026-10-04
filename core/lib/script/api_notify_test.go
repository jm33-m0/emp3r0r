package script

import (
	"strings"
	"testing"
)

// TestNotifyBuiltinStreams proves the `notify` builtin hands each message to
// the run's notifier as it is produced, rather than waiting for the script to
// return.
func TestNotifyBuiltinStreams(t *testing.T) {
	var got []string
	src := `
def main(*args):
    notify("first")
    notify("second")
    return "OK"
`
	out, err := Run([]byte(src), nil, nil, 0, WithNotifier(func(msg string) {
		got = append(got, msg)
	}))
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("notifier got %v, want [first second]", got)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("script output missing OK:\n%s", out)
	}
}

// TestNotifyBuiltinWithoutNotifier proves the builtin is harmless when no
// sender is wired (standalone tools and tests): it must not fail the script.
func TestNotifyBuiltinWithoutNotifier(t *testing.T) {
	src := `
def main(*args):
    notify("dropped")
    return "OK"
`
	out, err := Run([]byte(src), nil, nil, 0)
	if err != nil {
		t.Fatalf("Run without notifier: %v\n%s", err, out)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("script output missing OK:\n%s", out)
	}
}
