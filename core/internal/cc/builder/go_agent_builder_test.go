package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestGoAgentSourceDirPrefersWorkspace(t *testing.T) {
	oldWS, oldData := live.EmpWorkSpace, live.EmpDataDir
	live.EmpWorkSpace, live.EmpDataDir = t.TempDir(), t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace, live.EmpDataDir = oldWS, oldData })
	dir := filepath.Join(live.EmpWorkSpace, GoAgentSourceDirName)
	if err := os.MkdirAll(filepath.Join(dir, "cmd", "agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", GoAgentBuildScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := GoAgentSourceDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("source dir = %q, want %q", got, dir)
	}
}

func TestBuildGoAgentStubInvokesShippedBuilder(t *testing.T) {
	oldWS := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWS })
	source := t.TempDir()
	script := `import pathlib, sys
args = sys.argv[1:]
out = args[args.index("--payload-output") + 1]
pathlib.Path(out).write_text(" ".join(args))
`
	if err := os.WriteFile(filepath.Join(source, GoAgentBuildScript), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "stub")
	err := BuildGoAgentStub(AgentBuildConfig{
		PayloadType: PayloadTypeLinuxExecutable,
		Arch:        "amd64",
		BuildTags:   []string{"with_mesh", "with_kcp"},
	}, source, out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"--payload-kind cgo", "--agent-tags with_mesh with_kcp", "--payload-magic-string"} {
		if !strings.Contains(got, want) {
			t.Fatalf("builder args = %q, missing %q", got, want)
		}
	}
}
