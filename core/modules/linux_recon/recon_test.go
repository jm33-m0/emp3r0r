//go:build linux

// Package linux_recon contains the Linux Starlark recon modules and their
// tests. The runtime artifacts (config.json, *.star) are consumed by the C2
// module loader; this test package exercises the scripts through the real
// embedded Starlark engine.
package linux_recon

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

// runModule loads a shipped .star file and executes it through the engine,
// returning captured output. A script error fails the test.
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

func sleepBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary not found")
	}
	return path
}

// startNamedProcess execs sleep through a symlink whose basename is name, so
// the child's /proc/<pid>/comm matches an EDR fingerprint. Returns the child
// after confirming the kernel published the comm.
func startNamedProcess(t *testing.T, name string) *exec.Cmd {
	t.Helper()
	sleep := sleepBinary(t)
	link := filepath.Join(t.TempDir(), name)
	if err := os.Symlink(sleep, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	cmd := exec.Command(link, "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pid := cmd.Process.Pid
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if strings.TrimSpace(string(b)) == name {
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child %d never reported comm %q", pid, name)
	return nil
}

func startSecretProcess(t *testing.T, key, value string) *exec.Cmd {
	t.Helper()
	sleep := sleepBinary(t)
	cmd := exec.Command(sleep, "60")
	cmd.Env = append(os.Environ(), key+"="+value)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start secret holder: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pid := cmd.Process.Pid
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if strings.Contains(string(b), key+"=") {
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child %d never exposed %s in /proc/%d/environ", pid, key, pid)
	return nil
}

// TestModulesSmoke asserts every shipped script parses and runs end to end.
func TestModulesSmoke(t *testing.T) {
	cases := []struct {
		file string
		argv []string
	}{
		{"edr_recon.star", []string{"procs,arts,mods,lsm"}},
		{"edr_recon.star", []string{"bpf"}},
		{"env_scrape.star", []string{"secrets", "own"}},
		{"proc_fd_scan.star", []string{"", ""}},
		{"sysctl_audit.star", nil},
	}
	for _, c := range cases {
		out := runModule(t, c.file, c.argv)
		if !strings.Contains(out, "OK") {
			t.Errorf("%s did not return OK:\n%s", c.file, out)
		}
	}
}

// TestEDRReconDetectsProcess plants a process whose comm matches the
// CrowdStrike profile and requires the audit to attribute it.
func TestEDRReconDetectsProcess(t *testing.T) {
	cmd := startNamedProcess(t, "falcon-sensor")
	out := runModule(t, "edr_recon.star", []string{"procs"})

	if !strings.Contains(out, "CrowdStrike Falcon") {
		t.Fatalf("falcon-sensor not attributed to CrowdStrike:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("pid=%d", cmd.Process.Pid)) {
		t.Fatalf("pid %d missing from recon output:\n%s", cmd.Process.Pid, out)
	}
	if !strings.Contains(out, "score=") {
		t.Fatalf("detection summary missing a score:\n%s", out)
	}
}

// TestEnvScrapeFindsSecret plants a secret-bearing process and requires the
// scraper to surface the exact key/value.
func TestEnvScrapeFindsSecret(t *testing.T) {
	const key = "AWS_SECRET_ACCESS_KEY"
	const val = "emp3r0r-recon-selftest"
	startSecretProcess(t, key, val)

	out := runModule(t, "env_scrape.star", []string{"secrets", "all"})
	want := key + "=" + val
	if !strings.Contains(out, want) {
		t.Fatalf("secret %q not reported:\n%s", want, out)
	}
	if !strings.Contains(out, "[SECRET]") {
		t.Fatalf("secret was not tagged [SECRET]:\n%s", out)
	}

	// ssh mode must not report a non-SSH secret.
	sshOut := runModule(t, "env_scrape.star", []string{"ssh", "all"})
	if strings.Contains(sshOut, want) {
		t.Fatalf("ssh mode leaked a non-SSH secret:\n%s", sshOut)
	}
}

// TestProcFDScanFindsOpenCredentialFile holds an fd open on a credential-named
// path and requires the scan to report that process/fd.
func TestProcFDScanFindsOpenCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_rsa")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	out := runModule(t, "proc_fd_scan.star", []string{"", ""})
	if !strings.Contains(out, path) {
		t.Fatalf("open credential file %s not reported:\n%s", path, out)
	}
	if !strings.Contains(out, "pid=") || !strings.Contains(out, "fd=") {
		t.Fatalf("fd report did not include pid/fd:\n%s", out)
	}
}

// TestProcFDScanFilter verifies a user filter overrides the built-in list.
func TestProcFDScanFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unremarkable-name")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	out := runModule(t, "proc_fd_scan.star", []string{"unremarkable-name", ""})
	if !strings.Contains(out, path) {
		t.Fatalf("filter did not match %s:\n%s", path, out)
	}
}

// TestSysctlAuditMatchesKernel cross-checks reported values against the real
// sysctl files rather than trusting the script's formatting.
func TestSysctlAuditMatchesKernel(t *testing.T) {
	out := runModule(t, "sysctl_audit.star", nil)
	checks := []string{
		"kernel/dmesg_restrict",
		"kernel/kptr_restrict",
		"kernel/perf_event_paranoid",
		"kernel/modules_disabled",
	}
	for _, name := range checks {
		var line string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, name) {
				line = l
				break
			}
		}
		if line == "" {
			t.Errorf("linux_sysctl_audit did not report %s:\n%s", name, out)
			continue
		}
		b, err := os.ReadFile("/proc/sys/" + name)
		if err != nil {
			continue // some sysctls are unreadable in sandboxes
		}
		val := strings.TrimSpace(string(b))
		if val != "" && !strings.Contains(line, val) {
			t.Errorf("line %q does not contain kernel value %q", line, val)
		}
	}
}
