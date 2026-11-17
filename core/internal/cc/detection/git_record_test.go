package detection

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func newGitTestRecorder(t *testing.T) (*gitRecorder, sourceRoot, string) {
	t.Helper()
	moduleDir := t.TempDir()
	for name, body := range map[string]string{
		"a.c":      "int a(void){return 0;}\n",
		"build.sh": "#!/bin/sh\nexit 0\n",
		"out.exe":  "not source\n",
	} {
		if err := os.WriteFile(filepath.Join(moduleDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(moduleDir, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "build", "ignored.c"), []byte("generated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := newSourceRoots("loader_windows", sourceRoot{Name: "loader_windows", Dir: moduleDir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := newGitRecorder(t.TempDir(), "loop", roots, func(logging.Class, string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	root, err := recorder.rootByName("loader_windows")
	if err != nil {
		t.Fatal(err)
	}
	return recorder, root, moduleDir
}

func TestGitRecorderRecordsSourceOnly(t *testing.T) {
	ctx := context.Background()
	recorder, root, moduleDir := newGitTestRecorder(t)
	if err := recorder.Init(ctx); err != nil {
		t.Fatal(err)
	}
	baselineLog, err := recorder.Log(ctx, root, 1)
	if err != nil || strings.TrimSpace(baselineLog) == "" {
		t.Fatalf("baseline commit was not recorded: %v", err)
	}
	baseline := strings.Fields(baselineLog)[0]
	shadow := recorder.workTree(root)
	for _, want := range []string{"a.c", "build.sh"} {
		if _, err := os.Stat(filepath.Join(shadow, want)); err != nil {
			t.Fatalf("shadow tree is missing %s: %v", want, err)
		}
	}
	for _, unwanted := range []string{"out.exe", filepath.Join("build", "ignored.c")} {
		if _, err := os.Stat(filepath.Join(shadow, unwanted)); !os.IsNotExist(err) {
			t.Fatalf("shadow tree contains non-source file %s", unwanted)
		}
	}

	if err := os.WriteFile(filepath.Join(moduleDir, "a.c"), []byte("int a(void){return 1;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "b.c"), []byte("int b(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := recorder.Commit(ctx, root, "cycle 1: section-map")
	if err != nil {
		t.Fatal(err)
	}
	if second == "" || second == baseline {
		t.Fatalf("cycle commit = %q, baseline = %q", second, baseline)
	}
	log, err := recorder.Log(ctx, root, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"baseline", "cycle 1", "a.c", "b.c"} {
		if !strings.Contains(log, want) {
			t.Fatalf("log missing %q:\n%s", want, log)
		}
	}
	show, err := recorder.Show(ctx, root, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cycle 1", "a.c", "b.c"} {
		if !strings.Contains(show, want) {
			t.Fatalf("show missing %q:\n%s", want, show)
		}
	}
	if _, err := recorder.Show(ctx, root, "not-a-commit"); err == nil {
		t.Fatal("invalid commit was accepted")
	}
}

func TestGitHistoryTool(t *testing.T) {
	ctx := context.Background()
	recorder, root, moduleDir := newGitTestRecorder(t)
	if err := recorder.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "a.c"), []byte("int a(void){return 2;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	head, err := recorder.Commit(ctx, root, "cycle 1")
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg:  EvolveConfig{Module: "loader_windows", StoreRoot: t.TempDir()},
		git:  recorder,
		logf: func(logging.Class, string, ...any) {},
	}
	res, err := e.gitHistoryTool().Call(ctx, json.RawMessage(`{"limit":5}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("GitHistory: %v %+v", err, res)
	}
	if !strings.Contains(res.Flatten(), "cycle 1") {
		t.Fatalf("GitHistory output = %s", res.Flatten())
	}
	res, err = e.gitHistoryTool().Call(ctx, json.RawMessage(`{"commit":"`+head+`"}`), nil)
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "a.c") {
		t.Fatalf("GitHistory show: %v %+v", err, res)
	}
	res, err = e.gitHistoryTool().Call(ctx, json.RawMessage(`{"root":"nope"}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("GitHistory accepted an unknown root: %v %+v", err, res)
	}
}
