package operator

import (
	"context"
	"testing"
)

func TestSplitCommandLine(t *testing.T) {
	got, err := SplitCommandLine(`exec --cmd "echo hello world" --path '/tmp/a b'`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"exec", "--cmd", "echo hello world", "--path", "/tmp/a b"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestSplitCommandLineRejectsUnterminatedQuote(t *testing.T) {
	if _, err := SplitCommandLine(`exec --cmd "echo`); err == nil {
		t.Fatal("unterminated quote was accepted")
	}
}

func TestHeadlessCommandRejectsExit(t *testing.T) {
	if err := HeadlessCommand(context.Background(), "/exit"); err == nil {
		t.Fatal("exit was accepted")
	}
}

func TestHeadlessCommandRunsHelp(t *testing.T) {
	if err := HeadlessCommand(context.Background(), "/help"); err != nil {
		t.Fatal(err)
	}
}

func TestSplitCommandLinePreservesWindowsPaths(t *testing.T) {
	got, err := SplitCommandLine(`cat C:\Windows\System32\drivers\etc\hosts`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cat", `C:\Windows\System32\drivers\etc\hosts`}
	if len(got) != len(want) || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
}
