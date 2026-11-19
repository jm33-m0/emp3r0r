package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func TestLoopManifestRoundTripAndOnDiskListing(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	resetDetectRunsForTest()
	t.Cleanup(resetDetectRunsForTest)

	stateStore := filepath.Join(live.EmpWorkSpace, "detection")
	opts := detectLoopOptions{
		ModuleDir:  filepath.Join(stateStore, "module"),
		Shellcode:  filepath.Join(stateStore, "shellcode.bin"),
		Iterations: 7,
		AgentType:  "windows_dll",
		Goal:       "resume me",
	}
	manifest := &detectLoopManifest{
		LoopID:        "loop-state",
		BaseLoopID:    "loop-state",
		CurrentLoopID: "loop-state-r2",
		Attempt:       2,
		Status:        "stopped",
		StartedAt:     time.Now().Add(-time.Hour).UTC(),
		Options:       opts,
	}
	if err := writeDetectLoopManifest(manifest); err != nil {
		t.Fatal(err)
	}

	byBase, err := readDetectLoopManifest("loop-state")
	if err != nil {
		t.Fatal(err)
	}
	if byBase.Options.Shellcode != opts.Shellcode || byBase.Options.Iterations != opts.Iterations {
		t.Fatalf("manifest options not preserved: %+v", byBase.Options)
	}
	byAttempt, err := readDetectLoopManifest("loop-state-r2")
	if err != nil {
		t.Fatal(err)
	}
	if byAttempt.CurrentLoopID != "loop-state-r2" {
		t.Fatalf("attempt lookup returned %+v", byAttempt)
	}

	// A report-only loop predates manifests. It must still be visible, but it
	// is not resumable because its original options are lost.
	reports := filepath.Join(stateStore, "reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reports, "loop-old.md"), []byte("# old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	infos := listDetectRunInfos()
	byID := map[string]detectRunInfo{}
	for _, info := range infos {
		byID[info.LoopID] = info
	}
	resumable, ok := byID["loop-state"]
	if !ok {
		t.Fatalf("on-disk manifest missing from list: %+v", infos)
	}
	if !resumable.OnDisk || !resumable.Resumable || resumable.Attempt != 2 || resumable.ResumeAttempt != 3 {
		t.Fatalf("resumable row = %+v", resumable)
	}
	if resumable.Status != "stopped" {
		t.Fatalf("manifest status = %q, want stopped", resumable.Status)
	}
	old, ok := byID["loop-old"]
	if !ok {
		t.Fatalf("report-only loop missing from list: %+v", infos)
	}
	if old.Resumable {
		t.Fatalf("report-only loop was marked resumable: %+v", old)
	}
}

func TestRemoveFinishedDetectRunAllowsResume(t *testing.T) {
	resetDetectRunsForTest()
	t.Cleanup(resetDetectRunsForTest)
	run, err := registerDetectRun("loop-done", nil, "/tmp/loop-done.log", nil)
	if err != nil {
		t.Fatal(err)
	}
	run.finish()
	if err := removeFinishedDetectRun("loop-done"); err != nil {
		t.Fatal(err)
	}
	if findDetectRun("loop-done") != nil {
		t.Fatal("finished run was not removed from the registry")
	}
	if _, err := registerDetectRun("loop-done", nil, "/tmp/loop-done.log", nil); err != nil {
		t.Fatalf("re-register after removing finished run: %v", err)
	}
}

func TestLoopManifestInterruptedStatus(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	resetDetectRunsForTest()
	t.Cleanup(resetDetectRunsForTest)

	manifests, err := listDetectLoopManifests()
	if err != nil || len(manifests) != 0 {
		t.Fatalf("empty state = %+v, %v", manifests, err)
	}
	manifest := &detectLoopManifest{
		LoopID: "loop-running", BaseLoopID: "loop-running", Attempt: 1, Status: "running",
		StartedAt: time.Now().UTC(),
	}
	if err := writeDetectLoopManifest(manifest); err != nil {
		t.Fatal(err)
	}
	infos := listDetectRunInfos()
	if len(infos) != 1 || infos[0].Status != "interrupted" {
		t.Fatalf("interrupted manifest = %+v", infos)
	}
}

func TestDetectLoopListCommandShowsOnDiskLoop(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	resetDetectRunsForTest()
	t.Cleanup(resetDetectRunsForTest)

	manifest := &detectLoopManifest{
		LoopID: "loop-listed", BaseLoopID: "loop-listed", Attempt: 1, Status: "stopped",
		StartedAt: time.Now().UTC(),
	}
	if err := writeDetectLoopManifest(manifest); err != nil {
		t.Fatal(err)
	}
	cmd := detectLoopListCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.Run(cmd, nil)
	if !strings.Contains(out.String(), "loop-listed") || !strings.Contains(out.String(), "yes") {
		t.Fatalf("list output missing on-disk loop: %q", out.String())
	}
}

func TestSaveLoopManifestUpdatesAttempt(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })

	opts := detectLoopOptions{ModuleDir: "/tmp/module", Shellcode: "/tmp/payload", Iterations: 9}
	run := &detectRun{logPath: "/tmp/loop.log", started: time.Now().UTC()}
	saveLoopManifest("loop-save", "loop-save-r2", 2, "running", opts, run)
	manifest, err := readDetectLoopManifest("loop-save-r2")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Attempt != 2 || manifest.CurrentLoopID != "loop-save-r2" || manifest.Status != "running" {
		t.Fatalf("updated manifest = %+v", manifest)
	}
	if manifest.Options.Shellcode != opts.Shellcode || manifest.Options.Iterations != opts.Iterations {
		t.Fatalf("saved options = %+v", manifest.Options)
	}
}

func TestManifestTightensStatePermissions(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	dir := detectLoopStateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeDetectLoopManifest(&detectLoopManifest{LoopID: "loop-perm", BaseLoopID: "loop-perm"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %o, want 700", info.Mode().Perm())
	}
	info, err = os.Stat(detectLoopManifestPath("loop-perm"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCompletedManifestIsNotResumable(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	resetDetectRunsForTest()
	t.Cleanup(resetDetectRunsForTest)
	for _, status := range []string{"verified", "done"} {
		id := "loop-" + status
		if err := writeDetectLoopManifest(&detectLoopManifest{LoopID: id, BaseLoopID: id, Attempt: 1, Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	byID := map[string]detectRunInfo{}
	for _, info := range listDetectRunInfos() {
		byID[info.LoopID] = info
	}
	for _, status := range []string{"verified", "done"} {
		info := byID["loop-"+status]
		if info.Resumable || info.ResumeAttempt != 0 {
			t.Fatalf("%s loop marked resumable: %+v", status, info)
		}
	}
}

func TestSaveLoopManifestRecordsFailure(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	run := &detectRun{logPath: "/tmp/loop.log", started: time.Now().UTC()}
	run.setError(os.ErrPermission)
	saveLoopManifest("loop-failed", "loop-failed", 1, "failed", detectLoopOptions{}, run)
	m, err := readDetectLoopManifest("loop-failed")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != "failed" || m.Error == "" {
		t.Fatalf("failed manifest = %+v", m)
	}
}

func TestDetectLoopLogPathStaysInDetectionStore(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	root := filepath.Join(live.EmpWorkSpace, "detection")
	inside := filepath.Join(root, "inside.log")
	if got := detectLoopLogPath(inside); got != inside {
		t.Fatalf("inside log path = %q, want %q", got, inside)
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	got := detectLoopLogPath(outside)
	if got == outside || !strings.HasPrefix(got, root+string(os.PathSeparator)) {
		t.Fatalf("outside log path = %q, want a path under %q", got, root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.log")
	if err := os.Symlink(outside, link); err == nil {
		if got := detectLoopLogPath(link); got == link {
			t.Fatalf("symlink log path was accepted: %q", got)
		}
	}
}

func TestFailedManifestIsResumable(t *testing.T) {
	if !detectLoopResumable("failed") || !detectLoopResumable("interrupted") || detectLoopResumable("done") {
		t.Fatal("resumable status classification is wrong")
	}
}

func TestManifestStoresAbsolutePathsForResume(t *testing.T) {
	oldWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = oldWorkspace })
	opts := detectLoopOptions{
		ModuleDir: "relative/module",
		Shellcode: "relative/agent.bin",
		ReadRoots: []string{"relative/read"},
	}
	saveLoopManifest("loop-relative", "loop-relative", 1, "running", opts, &detectRun{started: time.Now().UTC()})
	m, err := readDetectLoopManifest("loop-relative")
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"module": m.Options.ModuleDir, "shellcode": m.Options.Shellcode, "read root": m.Options.ReadRoots[0],
	} {
		if !filepath.IsAbs(path) {
			t.Fatalf("%s path = %q, want absolute", name, path)
		}
	}
}
