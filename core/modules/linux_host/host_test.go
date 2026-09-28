//go:build linux

// Package linux_host contains the Linux host-control Starlark modules and
// their tests. The runtime artifacts (config.json, *.star) are consumed by the
// C2 module loader; this test package drives them through the real embedded
// Starlark engine.
package linux_host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/script"
)

func runModule(t *testing.T, file string, argv []string) string {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	out, err := script.Run(src, argv, nil, 0)
	if err != nil {
		t.Fatalf("%s failed: %v\noutput:\n%s", file, err, out)
	}
	return out
}

// TestTimeStompSetsMtime proves the utimensat call actually changes the file,
// not just that the script runs.
func TestTimeStompSetsMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	out := runModule(t, "time_stomp.star", []string{"set", path, "1600000000"})
	if !strings.Contains(out, "OK") {
		t.Fatalf("script did not return OK:\n%s", out)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.ModTime().Unix(); got != 1600000000 {
		t.Fatalf("mtime = %d, want 1600000000", got)
	}

	// zero must land on the unix epoch.
	runModule(t, "time_stomp.star", []string{"zero", path, "0"})
	if st, _ := os.Stat(path); st.ModTime().Unix() != 0 {
		t.Fatalf("zero mode mtime = %d, want 0", st.ModTime().Unix())
	}
}

// TestTimeStompMissingPath verifies the guard rather than an engine exception.
func TestTimeStompMissingPath(t *testing.T) {
	out := runModule(t, "time_stomp.star", []string{"now", "", "0"})
	if !strings.Contains(out, "path required") {
		t.Fatalf("expected a path-required message:\n%s", out)
	}
}

// TestOomCageShowAndSet reads the real /proc value and verifies a write of the
// current value round-trips.
func TestOomCageShowAndSet(t *testing.T) {
	out := runModule(t, "oom_cage.star", []string{"show", "", ""})
	if !strings.Contains(out, "oom_score_adj=") || !strings.Contains(out, "oom_score=") {
		t.Fatalf("show output missing fields:\n%s", out)
	}

	raw, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		t.Skipf("cannot read oom_score_adj: %v", err)
	}
	cur := strings.TrimSpace(string(raw))

	setOut := runModule(t, "oom_cage.star", []string{"set", "", cur})
	if !strings.Contains(setOut, "OK") {
		t.Fatalf("set of current value did not succeed:\n%s", setOut)
	}
	after, _ := os.ReadFile("/proc/self/oom_score_adj")
	if strings.TrimSpace(string(after)) != cur {
		t.Fatalf("oom_score_adj changed from %q to %q", cur, strings.TrimSpace(string(after)))
	}
}

// TestCgroupFreezeShowAndGuard verifies the read path and that the agent
// refuses to freeze its own cgroup.
func TestCgroupFreezeShowAndGuard(t *testing.T) {
	out := runModule(t, "cgroup_freeze.star", []string{"show", ""})
	if !strings.Contains(out, "cgroup=") {
		t.Fatalf("show output missing cgroup info:\n%s", out)
	}

	guard := runModule(t, "cgroup_freeze.star", []string{"freeze", ""})
	if !strings.Contains(guard, "refusing") {
		t.Fatalf("freeze of own cgroup was not refused:\n%s", guard)
	}
}

// TestHostModulesSmoke asserts every module parses and runs against safe args.
func TestHostModulesSmoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smoke")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cases := []struct {
		file string
		argv []string
	}{
		{"time_stomp.star", []string{"now", path, "0"}},
		{"oom_cage.star", []string{"show", "", ""}},
		{"cgroup_freeze.star", []string{"show", ""}},
	}
	for _, c := range cases {
		out := runModule(t, c.file, c.argv)
		if !strings.Contains(out, "OK") {
			t.Errorf("%s did not return OK:\n%s", c.file, out)
		}
	}
}
