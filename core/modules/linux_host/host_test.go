//go:build linux

// Package linux_host contains the Linux host-control Starlark modules and
// their tests. The runtime artifacts (config.json, *.star) are consumed by the
// C2 module loader; this test package drives them through the real embedded
// Starlark engine.
//
// These tests exercise real kernel interfaces (utimensat, oom_score_adj,
// cgroup v2, pidfd_getfd). Some require root; they skip locally when the
// capability is missing but are expected to run as root.
package linux_host

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
}

// startSleep launches a real child process and guarantees it is reaped.
func startSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary not found")
	}
	cmd := exec.Command(sleep, "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
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

// TestTimeStompNowMode stamps an old file and requires it to come back to the
// present.
func TestTimeStompNowMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	runModule(t, "time_stomp.star", []string{"now", path, "0"})
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if delta := time.Since(st.ModTime()); delta < 0 || delta > 10*time.Second {
		t.Fatalf("now mode mtime = %s (delta %s), want ~now", st.ModTime(), delta)
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
		t.Fatalf("cannot read oom_score_adj: %v", err)
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

// TestOomCageExposeTarget raises a child's score, which is allowed without
// privilege and must be visible in /proc.
func TestOomCageExposeTarget(t *testing.T) {
	cmd := startSleep(t)
	pid := fmt.Sprintf("%d", cmd.Process.Pid)

	out := runModule(t, "oom_cage.star", []string{"expose", pid, ""})
	if !strings.Contains(out, "OK") {
		t.Fatalf("expose failed:\n%s", out)
	}
	raw, err := os.ReadFile("/proc/" + pid + "/oom_score_adj")
	if err != nil {
		t.Fatalf("read target adj: %v", err)
	}
	if strings.TrimSpace(string(raw)) != "1000" {
		t.Fatalf("target oom_score_adj = %q, want 1000", strings.TrimSpace(string(raw)))
	}
}

// TestOomCageProtectTarget lowers a child's score, which needs
// CAP_SYS_RESOURCE, and must leave -1000 in /proc.
func TestOomCageProtectTarget(t *testing.T) {
	requireRoot(t)
	cmd := startSleep(t)
	pid := fmt.Sprintf("%d", cmd.Process.Pid)

	out := runModule(t, "oom_cage.star", []string{"protect", pid, ""})
	if strings.Contains(out, "CAP_SYS_RESOURCE") {
		t.Skipf("CAP_SYS_RESOURCE unavailable: %s", strings.TrimSpace(out))
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("protect failed:\n%s", out)
	}
	raw, err := os.ReadFile("/proc/" + pid + "/oom_score_adj")
	if err != nil {
		t.Fatalf("read target adj: %v", err)
	}
	if strings.TrimSpace(string(raw)) != "-1000" {
		t.Fatalf("target oom_score_adj = %q, want -1000", strings.TrimSpace(string(raw)))
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

// TestCgroupFreezeTarget moves a real child into a dedicated cgroup v2 and
// verifies freeze/thaw flip cgroup.freeze.
func TestCgroupFreezeTarget(t *testing.T) {
	requireRoot(t)
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("cgroup v2 not mounted")
	}

	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary not found")
	}
	cmd := exec.Command(sleep, "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	pid := cmd.Process.Pid

	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("emp3r0r_test_%d", time.Now().UnixNano()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Skipf("cannot create cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(cg)
	})

	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(fmt.Sprintf("%d\n", pid)), 0o644); err != nil {
		t.Skipf("cannot move child into cgroup: %v", err)
	}

	out := runModule(t, "cgroup_freeze.star", []string{"freeze", fmt.Sprintf("%d", pid)})
	if !strings.Contains(out, "frozen") {
		t.Skipf("cannot freeze cgroup in this environment: %s", strings.TrimSpace(out))
	}
	raw, _ := os.ReadFile(filepath.Join(cg, "cgroup.freeze"))
	if strings.TrimSpace(string(raw)) != "1" {
		t.Fatalf("cgroup.freeze = %q, want 1", strings.TrimSpace(string(raw)))
	}

	out = runModule(t, "cgroup_freeze.star", []string{"thaw", fmt.Sprintf("%d", pid)})
	if !strings.Contains(out, "thaw") {
		t.Fatalf("thaw did not report success:\n%s", out)
	}
	raw, _ = os.ReadFile(filepath.Join(cg, "cgroup.freeze"))
	if strings.TrimSpace(string(raw)) != "0" {
		t.Fatalf("cgroup.freeze = %q, want 0", strings.TrimSpace(string(raw)))
	}
}

// TestFDStealReadsHeldFile proves pidfd_getfd duplicates a descriptor out of
// the target and the content is read back, without the agent opening the path.
func TestFDStealReadsHeldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	want := "id_rsa_secret_value=abc123"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	out := runModule(t, "pidfd_steal.star", []string{
		fmt.Sprintf("%d", os.Getpid()),
		fmt.Sprintf("%d", f.Fd()),
		"4096",
	})
	if !strings.Contains(out, want) {
		t.Fatalf("stolen content not reported:\n%s", out)
	}
}

// TestFDStealRefusesPipe ensures a blocking read on a pipe is refused rather
// than hanging the agent.
func TestFDStealRefusesPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	out := runModule(t, "pidfd_steal.star", []string{
		fmt.Sprintf("%d", os.Getpid()),
		fmt.Sprintf("%d", r.Fd()),
		"4096",
	})
	if !strings.Contains(out, "non-regular") {
		t.Fatalf("pipe target was not refused:\n%s", out)
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
	// pidfd_steal round-trip against our own process, run last so earlier
	// assertions are unaffected.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open smoke: %v", err)
	}
	defer f.Close()
	out := runModule(t, "pidfd_steal.star", []string{
		fmt.Sprintf("%d", os.Getpid()),
		fmt.Sprintf("%d", f.Fd()),
		"64",
	})
	if !strings.Contains(out, "x") {
		t.Errorf("pidfd_steal smoke did not read the file:\n%s", out)
	}
}
