//go:build linux

// Package linux_blind contains the Linux evasion/anti-forensics Starlark
// modules and their tests. The runtime artifacts (config.json, *.star) are
// consumed by the C2 module loader; this test package drives them through the
// real embedded Starlark engine.
//
// Privileged tests (mounts, /proc hiding, cgroups, dmesg, module info) require
// root and are expected to run in a real root environment; they skip when the
// capability is absent so a non-root `go test` still builds and runs the
// unprivileged tests.
package linux_blind

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"golang.org/x/sys/unix"
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

// skipIfNoCap turns a capability refusal into a skip so the privileged tests
// degrade cleanly in a rootless/container environment.
func skipIfNoCap(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "CAP_SYS_ADMIN required") || strings.Contains(out, "root required") {
		t.Skipf("environment lacks the required capability: %s", strings.TrimSpace(out))
	}
}

// mountSource returns the device/source bound on target, or "".
func mountSource(target string) string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == target {
			return f[0]
		}
	}
	return ""
}

// cleanupUnmount detaches a test mount even if an assertion fails.
func cleanupUnmount(t *testing.T, target string) {
	t.Cleanup(func() { _ = unix.Unmount(target, unix.MNT_DETACH) })
}

// ----- linux_mmap_read -----

// TestMmapReadMatchesFile proves the mmap path returns the real file bytes.
func TestMmapReadMatchesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	want := "root:x:0:0:root:/root:/bin/bash\n"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := runModule(t, "mmap_read.star", []string{path, "65536"})
	if !strings.Contains(out, "OK") {
		t.Fatalf("script did not return OK:\n%s", out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("mmap read did not return file content:\n%s", out)
	}
}

// TestMmapReadHonorsCap checks the cap is enforced on the mapped length.
func TestMmapReadHonorsCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "long.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("A", 4096)), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out := runModule(t, "mmap_read.star", []string{path, "128"})
	if !strings.Contains(out, "(128 bytes, mmap)") {
		t.Fatalf("cap not honored:\n%s", out)
	}
}

// ----- linux_log_wipe -----

// TestLogWipePatternScrubsOnlyMatchingLines checks the filter path keeps the
// rest of the file intact.
func TestLogWipePatternScrubsOnlyMatchingLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte("line1\nsecret-line\nline2\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := runModule(t, "log_wipe.star", []string{"wipe", path, "secret", "", "false"})
	if !strings.Contains(out, "OK") {
		t.Fatalf("script did not return OK:\n%s", out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "line1\nline2\n" {
		t.Fatalf("filtered file = %q, want %q", got, "line1\nline2\n")
	}
}

// TestLogWipeTruncateEmptiesFile checks the no-pattern path truncates fully.
func TestLogWipeTruncateEmptiesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(path, []byte("a\nb\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	runModule(t, "log_wipe.star", []string{"wipe", path, "", "", "false"})
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != 0 {
		t.Fatalf("file size = %d, want 0", st.Size())
	}
}

// TestLogWipeDryRunDoesNotModify verifies the guard action leaves the file
// untouched.
func TestLogWipeDryRunDoesNotModify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure")
	content := "keep\nsecret\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := runModule(t, "log_wipe.star", []string{"wipe", path, "secret", "", "true"})
	if !strings.Contains(out, "would remove") {
		t.Fatalf("dry-run did not report the removal:\n%s", out)
	}
	got, _ := os.ReadFile(path)
	if string(got) != content {
		t.Fatalf("dry-run modified the file: %q", got)
	}
}

// TestLogWipeHistory truncates a real shell history in a throwaway HOME.
func TestLogWipeHistory(t *testing.T) {
	home := t.TempDir()
	hist := filepath.Join(home, ".bash_history")
	if err := os.WriteFile(hist, []byte("insider-command\n"), 0o600); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	out := runModule(t, "log_wipe.star", []string{"hist", "", "", home, "false"})
	if !strings.Contains(out, "OK") {
		t.Fatalf("hist did not return OK:\n%s", out)
	}
	st, err := os.Stat(hist)
	if err != nil {
		t.Fatalf("stat history: %v", err)
	}
	if st.Size() != 0 {
		t.Fatalf("history size = %d, want 0", st.Size())
	}
}

// ----- linux_kprobe_clear -----

// makeTracefs writes a kprobe_events file under a temp tracefs root.
func makeTracefs(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	events := filepath.Join(root, "kprobe_events")
	body := "p:myprobe do_sys_open dfd=%di\np:kprobes/g1/e1 vfs_read file=%di\n"
	if err := os.WriteFile(events, []byte(body), 0o600); err != nil {
		t.Fatalf("seed kprobe_events: %v", err)
	}
	return root, events
}

// TestKprobeClearDryRunAndApply proves the removal commands are derived from
// the event lines and appended to the events file only when not a dry run.
func TestKprobeClearDryRunAndApply(t *testing.T) {
	root, events := makeTracefs(t)

	out := runModule(t, "kprobe_clear.star", []string{"clear-kprobes", root, "true"})
	if !strings.Contains(out, "-:myprobe") || !strings.Contains(out, "-:kprobes/g1/e1") {
		t.Fatalf("dry-run did not derive correct removal commands:\n%s", out)
	}
	before, _ := os.ReadFile(events)
	if strings.Contains(string(before), "-:myprobe") {
		t.Fatalf("dry-run wrote to the events file")
	}

	runModule(t, "kprobe_clear.star", []string{"clear-kprobes", root, "false"})
	after, err := os.ReadFile(events)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if !strings.Contains(string(after), "-:myprobe") {
		t.Fatalf("clear did not append removals:\n%s", after)
	}
	if !strings.Contains(string(after), "-:kprobes/g1/e1") {
		t.Fatalf("clear did not append grouped removal:\n%s", after)
	}
}

// TestKprobeClearListReadsTracefs checks the read path over an override root.
func TestKprobeClearListReadsTracefs(t *testing.T) {
	root, _ := makeTracefs(t)
	out := runModule(t, "kprobe_clear.star", []string{"list", root, "false"})
	if !strings.Contains(out, "p:myprobe") {
		t.Fatalf("list did not show the seeded kprobe:\n%s", out)
	}
}

// TestKprobeClearTracingOff writes tracing_on and verifies it lands.
func TestKprobeClearTracingOff(t *testing.T) {
	root := t.TempDir()
	on := filepath.Join(root, "tracing_on")
	if err := os.WriteFile(on, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("seed tracing_on: %v", err)
	}
	out := runModule(t, "kprobe_clear.star", []string{"tracing-off", root, "false"})
	if !strings.Contains(out, "disabled") {
		t.Fatalf("tracing-off did not report success:\n%s", out)
	}
	data, _ := os.ReadFile(on)
	if strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("tracing_on = %q, want 0", strings.TrimSpace(string(data)))
	}
}

// ----- linux_sysctl_blind -----

// TestSysctlBlindShow checks the audit path against the live kernel.
func TestSysctlBlindShow(t *testing.T) {
	out := runModule(t, "sysctl_blind.star", []string{"show", "", "", "false"})
	if !strings.Contains(out, "kernel.kptr_restrict") || !strings.Contains(out, "kernel.perf_event_paranoid") {
		t.Fatalf("show output missing sysctls:\n%s", out)
	}
}

// TestSysctlBlindDryRun exercises the blind code path without writing.
func TestSysctlBlindDryRun(t *testing.T) {
	out := runModule(t, "sysctl_blind.star", []string{"blind", "", "", "true"})
	if !strings.Contains(out, "[dry-run]") || !strings.Contains(out, "kernel.kptr_restrict") {
		t.Fatalf("dry-run blind output missing changes:\n%s", out)
	}
}

// TestSysctlBlindSetCurrentValue writes back the value the kernel already
// reports; run as root this is a real write and read-back.
func TestSysctlBlindSetCurrentValue(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/kernel/kptr_restrict")
	if err != nil {
		t.Fatalf("cannot read kptr_restrict: %v", err)
	}
	cur := strings.TrimSpace(string(raw))

	out := runModule(t, "sysctl_blind.star", []string{"set", "kernel.kptr_restrict", cur, "false"})
	if strings.Contains(out, "ERROR: errno") {
		t.Skipf("kptr_restrict not writable here: %s", strings.TrimSpace(out))
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("set did not succeed:\n%s", out)
	}
	after, _ := os.ReadFile("/proc/sys/kernel/kptr_restrict")
	if strings.TrimSpace(string(after)) != cur {
		t.Fatalf("kptr_restrict changed from %q to %q", cur, strings.TrimSpace(string(after)))
	}
}

// ----- linux_dmesg_wipe -----

// TestDmesgWipeShowAndClear reads and then clears the kernel ring buffer. It
// needs CAP_SYSLOG, so it is root-only.
func TestDmesgWipeShowAndClear(t *testing.T) {
	requireRoot(t)
	out := runModule(t, "dmesg_wipe.star", []string{"show", ""})
	if strings.Contains(out, "ERROR: errno") {
		t.Skipf("CAP_SYSLOG unavailable: %s", strings.TrimSpace(out))
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("show failed:\n%s", out)
	}
	out = runModule(t, "dmesg_wipe.star", []string{"wipe", ""})
	if !strings.Contains(out, "cleared") {
		t.Fatalf("wipe failed:\n%s", out)
	}
}

// ----- linux_coredump_block -----

// TestCoredumpBlockShowAndSelf checks the read path and that `self` actually
// clears the process coredump_filter.
func TestCoredumpBlockShowAndSelf(t *testing.T) {
	show := runModule(t, "coredump_block.star", []string{"show", ""})
	if !strings.Contains(show, "coredump_filter:") || !strings.Contains(show, "dumpable:") {
		t.Fatalf("show output missing fields:\n%s", show)
	}

	self := runModule(t, "coredump_block.star", []string{"self", ""})
	if !strings.Contains(self, "coredump_filter=0: ok") {
		t.Fatalf("self did not report success:\n%s", self)
	}
	raw, err := os.ReadFile("/proc/self/coredump_filter")
	if err != nil {
		t.Fatalf("read coredump_filter: %v", err)
	}
	// The kernel renders coredump_filter as a hexadecimal bitmask, so a zeroed
	// filter reads back as "00000000" rather than "0".
	if strings.Trim(strings.TrimSpace(string(raw)), "0") != "" {
		t.Fatalf("coredump_filter = %q, want an all-zero mask", strings.TrimSpace(string(raw)))
	}
}

// TestCoredumpBlockMadvAppliesToVMAs checks madvise is invoked on the agent's
// own mappings.
func TestCoredumpBlockMadvAppliesToVMAs(t *testing.T) {
	out := runModule(t, "coredump_block.star", []string{"madv", ""})
	if !strings.Contains(out, "MADV_DONTDUMP applied to") {
		t.Fatalf("madv did not report applying to VMAs:\n%s", out)
	}
}

// TestCoredumpBlockTargetPid zeros a real child's coredump_filter. Writing the
// filter of one's own child needs no privilege.
func TestCoredumpBlockTargetPid(t *testing.T) {
	cmd := startSleep(t)
	pid := fmt.Sprintf("%d", cmd.Process.Pid)

	out := runModule(t, "coredump_block.star", []string{"pid", pid})
	if !strings.Contains(out, "OK") {
		t.Fatalf("pid action failed:\n%s", out)
	}
	raw, err := os.ReadFile("/proc/" + pid + "/coredump_filter")
	if err != nil {
		t.Fatalf("read target coredump_filter: %v", err)
	}
	if strings.Trim(strings.TrimSpace(string(raw)), "0") != "" {
		t.Fatalf("target coredump_filter = %q, want an all-zero mask", strings.TrimSpace(string(raw)))
	}
}

// ----- linux_vma_hide -----

// TestVmaHidePrimitives checks both mapping primitives run without error.
func TestVmaHidePrimitives(t *testing.T) {
	out := runModule(t, "vma_hide.star", []string{"dontdump", ""})
	if !strings.Contains(out, "MADV_DONTDUMP set") {
		t.Fatalf("dontdump failed:\n%s", out)
	}
	out = runModule(t, "vma_hide.star", []string{"name", "[heap]"})
	if strings.Contains(out, "errno=22") {
		// EINVAL means the kernel was built without CONFIG_ANON_VMA_NAME.
		t.Skipf("kernel does not support PR_SET_VMA_ANON_NAME: %s", out)
	}
	if !strings.Contains(out, "named [heap]") {
		t.Fatalf("name failed:\n%s", out)
	}
}

// ----- linux_self_delete -----

// TestSelfDeleteRemovesTarget proves unlinkat is used on the requested path.
func TestSelfDeleteRemovesTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out := runModule(t, "self_delete.star", []string{path})
	if !strings.Contains(out, "unlinked") {
		t.Fatalf("self_delete did not report success:\n%s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("target still exists: %v", err)
	}
}

// ----- linux_lkm_unload -----

// TestLkmUnloadList checks the read-only module enumeration.
func TestLkmUnloadList(t *testing.T) {
	out := runModule(t, "lkm_unload.star", []string{"list", "", "false"})
	if !strings.Contains(out, "module(s)") {
		t.Fatalf("list output missing summary:\n%s", out)
	}
}

// TestLkmUnloadHunt checks the EDR module scan path.
func TestLkmUnloadHunt(t *testing.T) {
	out := runModule(t, "lkm_unload.star", []string{"hunt", "", "false"})
	if !strings.Contains(out, "scanning for known EDR modules") {
		t.Fatalf("hunt output missing header:\n%s", out)
	}
}

// TestLkmUnloadInfo inspects a real loaded module from /proc/modules.
func TestLkmUnloadInfo(t *testing.T) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil || strings.TrimSpace(string(data)) == "" {
		t.Skip("no kernel modules loaded / not readable")
	}
	first := strings.Split(strings.TrimSpace(string(data)), "\n")[0]
	name := strings.Fields(first)[0]

	out := runModule(t, "lkm_unload.star", []string{"info", name, "false"})
	if !strings.Contains(out, "OK") || !strings.Contains(out, "holders:") {
		t.Fatalf("info %s failed:\n%s", name, out)
	}
}

// TestLkmUnloadMissingModule checks that the delete_module errno is surfaced
// rather than raising; a nonexistent module must never be unloaded.
func TestLkmUnloadMissingModule(t *testing.T) {
	out := runModule(t, "lkm_unload.star", []string{"unload", "emp3r0r_no_such_module", "false"})
	if strings.Contains(out, "missing CAP_SYS_MODULE") {
		t.Skipf("environment lacks CAP_SYS_MODULE: %s", strings.TrimSpace(out))
	}
	if !strings.Contains(out, "delete_module failed") && !strings.Contains(out, "unloaded") {
		t.Fatalf("unload did not report a result:\n%s", out)
	}
}

// ----- linux_mount_over -----

// TestMountOverList checks /proc/mounts parsing.
func TestMountOverList(t *testing.T) {
	out := runModule(t, "mount_over.star", []string{"list", "", "", "10m"})
	if !strings.Contains(out, "entries)") {
		t.Fatalf("list output missing entry count:\n%s", out)
	}
}

// TestMountOverBindAndUmount binds a source tree over a target and restores it.
func TestMountOverBindAndUmount(t *testing.T) {
	requireRoot(t)
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "marker"), []byte("bound"), 0o600); err != nil {
		t.Fatalf("seed src: %v", err)
	}

	out := runModule(t, "mount_over.star", []string{"bind", src, dst, ""})
	skipIfNoCap(t, out)
	cleanupUnmount(t, dst)
	if !strings.Contains(out, "bind-mounted") {
		t.Fatalf("bind did not report success:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dst, "marker")); err != nil {
		t.Fatalf("bind did not expose source: %v\n%s", err, out)
	}

	out = runModule(t, "mount_over.star", []string{"umount", "", dst, ""})
	if !strings.Contains(out, "unmounted") {
		t.Fatalf("umount did not report success:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dst, "marker")); !os.IsNotExist(err) {
		t.Fatalf("umount did not restore the target: %v", err)
	}
}

// TestMountOverTmpfsHidesContents mounts a tmpfs over a populated directory,
// proving the original contents are hidden, and restores them on unmount.
func TestMountOverTmpfsHidesContents(t *testing.T) {
	requireRoot(t)
	dst := t.TempDir()
	original := filepath.Join(dst, "original")
	if err := os.WriteFile(original, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := runModule(t, "mount_over.star", []string{"tmpfs", "", dst, "1m"})
	skipIfNoCap(t, out)
	cleanupUnmount(t, dst)
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatalf("tmpfs did not hide original contents: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dst, "new"), []byte("y"), 0o600); err != nil {
		t.Fatalf("write into tmpfs: %v", err)
	}

	out = runModule(t, "mount_over.star", []string{"umount", "", dst, ""})
	if !strings.Contains(out, "unmounted") {
		t.Fatalf("umount did not report success:\n%s", out)
	}
	if _, err := os.Stat(original); err != nil {
		t.Fatalf("original not restored after umount: %v", err)
	}
}

// TestMountOverHideFile shadows a real file with an empty one and restores it.
func TestMountOverHideFile(t *testing.T) {
	requireRoot(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out := runModule(t, "mount_over.star", []string{"hide", secret, "", ""})
	skipIfNoCap(t, out)
	shadow := mountSource(secret)
	t.Cleanup(func() {
		_ = unix.Unmount(secret, unix.MNT_DETACH)
		if shadow != "" {
			_ = os.RemoveAll(filepath.Dir(shadow))
		}
	})
	if !strings.Contains(out, "shadowed") {
		t.Fatalf("hide did not report success:\n%s", out)
	}
	data, err := os.ReadFile(secret)
	if err != nil {
		t.Fatalf("read shadowed file: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("file was not shadowed, got %q", data)
	}

	out = runModule(t, "mount_over.star", []string{"umount", "", secret, ""})
	if !strings.Contains(out, "unmounted") {
		t.Fatalf("umount did not report success:\n%s", out)
	}
	data, _ = os.ReadFile(secret)
	if string(data) != "TOPSECRET" {
		t.Fatalf("original not restored after umount: %q", data)
	}
}

// ----- linux_proc_hide -----

// TestProcHideList checks the hidden-PID report path.
func TestProcHideList(t *testing.T) {
	out := runModule(t, "proc_hide.star", []string{"list", "", ""})
	if !strings.Contains(out, "/proc/<pid> shadow mounts") {
		t.Fatalf("list output missing header:\n%s", out)
	}
}

// TestProcHideHideAndUnhide hides a real child's /proc entry and restores it.
func TestProcHideHideAndUnhide(t *testing.T) {
	requireRoot(t)
	cmd := startSleep(t)
	pid := fmt.Sprintf("%d", cmd.Process.Pid)
	target := "/proc/" + pid

	out := runModule(t, "proc_hide.star", []string{"hide", pid, ""})
	skipIfNoCap(t, out)
	shadow := mountSource(target)
	t.Cleanup(func() {
		_ = unix.Unmount(target, unix.MNT_DETACH)
		if shadow != "" {
			_ = os.RemoveAll(shadow)
		}
	})
	if !strings.Contains(out, "hidden") {
		t.Fatalf("hide did not report success:\n%s", out)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatalf("readdir target: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s not hidden: %d entries visible", target, len(entries))
	}

	out = runModule(t, "proc_hide.star", []string{"unhide", pid, ""})
	if !strings.Contains(out, "restored") {
		t.Fatalf("unhide did not report success:\n%s", out)
	}
	entries, err = os.ReadDir(target)
	if err != nil {
		t.Fatalf("readdir after unhide: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s still hidden after unhide", target)
	}
}

// ----- linux_tetragon_blind -----

// TestTetragonBlindScan checks the process scan path.
func TestTetragonBlindScan(t *testing.T) {
	out := runModule(t, "tetragon_blind.star", []string{"scan", "", ""})
	if !strings.Contains(out, "scanning for eBPF security processes") {
		t.Fatalf("scan output missing header:\n%s", out)
	}
}

// TestTetragonBlindRefusesOwnCgroup verifies freeze refuses the agent's own
// cgroup, so a blind action cannot take the agent down with it.
func TestTetragonBlindRefusesOwnCgroup(t *testing.T) {
	requireRoot(t)
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("cgroup v2 not mounted")
	}
	out := runModule(t, "tetragon_blind.star", []string{"freeze", fmt.Sprintf("%d", os.Getpid()), ""})
	if !strings.Contains(out, "refusing") {
		t.Fatalf("own cgroup was not refused:\n%s", out)
	}
}

// TestTetragonBlindKillExitedPid exercises the kill path against a reaped PID,
// which must surface ESRCH rather than raising.
func TestTetragonBlindKillExitedPid(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary not found")
	}
	cmd := exec.Command(sleep, "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()

	out := runModule(t, "tetragon_blind.star", []string{"kill", fmt.Sprintf("%d", pid), ""})
	if !strings.Contains(out, "errno=3") && !strings.Contains(out, "SIGKILL sent") {
		t.Fatalf("unexpected kill result:\n%s", out)
	}
}

// TestTetragonBlindDryRun drives the Furtex-derived blind sequence without
// touching the kernel. With no libbpf resolver the eBPF half degrades to a
// reported error, the freeze is skipped and no kill is sent.
func TestTetragonBlindDryRun(t *testing.T) {
	out := runModule(t, "tetragon_blind.star", []string{"blind", "self", "", "true", "false"})
	if !strings.Contains(out, "tetragon_blind sequence (dry-run)") {
		t.Fatalf("blind did not announce the sequence:\n%s", out)
	}
	if !strings.Contains(out, "[1] freezing pid self") {
		t.Fatalf("blind did not plan a freeze:\n%s", out)
	}
	if !strings.Contains(out, "[2] detaching monitoring BPF links") {
		t.Fatalf("blind did not plan detach:\n%s", out)
	}
	if !strings.Contains(out, "CAP_BPF") && !strings.Contains(out, "libbpf unavailable") {
		t.Fatalf("blind did not report the eBPF capability/dependency state:\n%s", out)
	}
	if !strings.Contains(out, "[+] done") {
		t.Fatalf("blind did not finish:\n%s", out)
	}
}

// TestTetragonBlindWipe checks the wipe action runs its map sweep and reports
// libbpf unavailability rather than raising when the dependency is absent.
func TestTetragonBlindWipe(t *testing.T) {
	out := runModule(t, "tetragon_blind.star", []string{"wipe", "", "", "true", "false"})
	if !strings.Contains(out, "wiping BPF event maps") {
		t.Fatalf("wipe did not run:\n%s", out)
	}
	if !strings.Contains(out, "CAP_BPF") && !strings.Contains(out, "libbpf unavailable") {
		t.Fatalf("wipe did not report the eBPF capability/dependency state:\n%s", out)
	}
}
