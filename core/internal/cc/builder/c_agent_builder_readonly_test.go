package builder

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// TestGenerateCAgentReadOnlySource pins that the on-demand build works when the
// installed source tree is read-only (e.g. under /usr): the builder must stage
// a writable copy instead of writing into the install prefix.
func TestGenerateCAgentReadOnlySource(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig is required to build the C agent")
	}
	coreDir, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	prefix := t.TempDir()
	caDir := filepath.Join(prefix, "c_agent")
	if err := util.Copy(filepath.Join(coreDir, "c_agent"), caDir); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Join(caDir, "build"))
	_ = filepath.WalkDir(caDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o555)
		}
		return nil
	})
	t.Cleanup(func() {
		_ = filepath.WalkDir(caDir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
	})

	tmp := t.TempDir()
	live.EmpDataDir = prefix
	live.EmpWorkSpace = tmp
	live.EmpConfigFile = filepath.Join(tmp, "emp3r0r.json")
	live.RuntimeConfig = &def.Config{}
	res, err := GenerateCAgentWorkflow(AgentConfig{}, CAgentProviders{}, nil)
	if err != nil {
		t.Fatalf("read-only build failed: %v", err)
	}
	if !util.IsFileExist(res.OutputFile) {
		t.Fatalf("output missing: %s", res.OutputFile)
	}
	t.Logf("built %s from read-only source", res.OutputFile)
}
