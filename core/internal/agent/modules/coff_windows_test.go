//go:build windows

package modules

import "testing"

func TestParseCOFFArgs(t *testing.T) {
	env := []string{
		"PATH=/bin",
		"args=zhello i42 bdeadbeef",
		"IGNORED=value",
	}

	args, err := parseCOFFArgs(env)
	if err != nil {
		t.Fatalf("parseCOFFArgs returned error: %v", err)
	}

	want := []string{"zhello", "i42", "bdeadbeef"}
	if len(args) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(args), len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d mismatch: got %s want %s", i, args[i], want[i])
		}
	}
}
