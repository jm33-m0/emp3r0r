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

func newSourceToolTestEvolver(t *testing.T) (*evolver, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	roots, err := newSourceRoots("module", sourceRoot{Name: "module", Dir: dir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg:   EvolveConfig{LoopID: "loop", Module: "module", ModuleDir: dir, Iterations: 20},
		db:    db,
		roots: roots,
		logf:  func(logging.Class, string, ...any) {},
	}
	return e, dir
}

func callTool(t *testing.T, e *evolver, name string, args any) toolResult {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	coreTool := e.editSourceTool()
	switch name {
	case "EditSource":
	case "SourceWrite":
		coreTool = e.sourceWriteTool()
	case "SourceMultiEdit":
		coreTool = e.sourceMultiEditTool()
	case "SourceDelete":
		coreTool = e.sourceDeleteTool()
	default:
		t.Fatalf("unknown tool %s", name)
	}
	result, err := coreTool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return toolResult{isError: result.IsError, text: result.Flatten()}
}

func TestSourceTreeHidesVendorAndHonorsDepth(t *testing.T) {
	e, dir := newSourceToolTestEvolver(t)
	for _, path := range []string{"internal/agent", "vendor/dep"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"internal/agent/main.go", "vendor/dep/dep.go", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := sourceTreeTool(e.roots).Call(context.Background(), json.RawMessage(`{"depth":3}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := result.Flatten()
	for _, want := range []string{"internal/", "agent/", "main.go", "README.md", "vendor/ (skipped"} {
		if !strings.Contains(out, want) {
			t.Fatalf("tree missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dep.go") {
		t.Fatalf("tree exposed vendor contents:\n%s", out)
	}
	result, err = sourceTreeTool(e.roots).Call(context.Background(), json.RawMessage(`{"include_vendor":true,"depth":2}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out := result.Flatten(); !strings.Contains(out, "dep/") {
		t.Fatalf("include_vendor did not reveal vendor:\n%s", out)
	}
	result, err = sourceTreeTool(e.roots).Call(context.Background(), json.RawMessage(`{"path":"internal","depth":1}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out := result.Flatten(); !strings.Contains(out, "agent/") || strings.Contains(out, "README.md") {
		t.Fatalf("scoped tree wrong:\n%s", out)
	}
}

func TestEditSourceReplaceAll(t *testing.T) {
	e, dir := newSourceToolTestEvolver(t)
	path := filepath.Join(dir, "a.go")
	if err := os.WriteFile(path, []byte("foo\nfoo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := callTool(t, e, "EditSource", map[string]any{
		"file": "a.go", "old_string": "foo", "new_string": "bar",
	}); !got.isError {
		t.Fatalf("non-unique edit without replace_all was accepted: %s", got.text)
	}
	if got := callTool(t, e, "EditSource", map[string]any{
		"file": "a.go", "old_string": "foo", "new_string": "bar", "replace_all": true,
	}); got.isError {
		t.Fatalf("replace_all failed: %s", got.text)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "bar\nbar\n" {
		t.Fatalf("replace_all = %q", data)
	}
}

func TestSourceWriteCreatesDirsAndReverts(t *testing.T) {
	e, dir := newSourceToolTestEvolver(t)
	content := "package agent\n\nfunc Run() {}\n"
	got := callTool(t, e, "SourceWrite", map[string]any{
		"file": "internal/newpkg/agent.go", "content": content, "reason": "new package",
	})
	if got.isError {
		t.Fatalf("SourceWrite failed: %s", got.text)
	}
	path := filepath.Join(dir, "internal/newpkg/agent.go")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != content {
		t.Fatalf("written file = %q err=%v", data, err)
	}
	if _, err := e.applyRevertEdits(context.Background(), []revertEdit{{
		id: 1, module: "module", file: "internal/newpkg/agent.go", old: "", new: content,
	}}, 1, "test"); err != nil {
		t.Fatalf("revert create: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("revert did not remove created file: %v", err)
	}
}

func TestSourceWriteOverwritesAndReverts(t *testing.T) {
	e, dir := newSourceToolTestEvolver(t)
	path := filepath.Join(dir, "agent.go")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := callTool(t, e, "SourceWrite", map[string]any{
		"file": "agent.go", "content": "new\n", "reason": "rewrite",
	})
	if got.isError {
		t.Fatalf("overwrite failed: %s", got.text)
	}
	if data, _ := os.ReadFile(path); string(data) != "new\n" {
		t.Fatalf("overwrite = %q", data)
	}
	var id int64
	if err := e.db.db.QueryRow(`SELECT id FROM loop_edits WHERE loop_id='loop' ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.applyRevertEdits(context.Background(), []revertEdit{{
		id: id, module: "module", file: "agent.go", old: "old\n", new: "new\n",
	}}, 1, "test"); err != nil {
		t.Fatalf("revert overwrite: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "old\n" {
		t.Fatalf("revert overwrite = %q", data)
	}
}

func TestSourceMultiEditIsAtomic(t *testing.T) {
	e, dir := newSourceToolTestEvolver(t)
	path := filepath.Join(dir, "a.go")
	if err := os.WriteFile(path, []byte("one two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := callTool(t, e, "SourceMultiEdit", map[string]any{
		"file": "a.go",
		"edits": []map[string]any{
			{"old_string": "one", "new_string": "ONE"},
			{"old_string": "missing", "new_string": "x"},
		},
	})
	if !got.isError {
		t.Fatalf("failed multi-edit was accepted: %s", got.text)
	}
	if data, _ := os.ReadFile(path); string(data) != "one two\n" {
		t.Fatalf("failed multi-edit changed the file: %q", data)
	}
	got = callTool(t, e, "SourceMultiEdit", map[string]any{
		"file": "a.go",
		"edits": []map[string]any{
			{"old_string": "one", "new_string": "ONE"},
			{"old_string": "two", "new_string": "TWO"},
		},
	})
	if got.isError {
		t.Fatalf("multi-edit failed: %s", got.text)
	}
	if data, _ := os.ReadFile(path); string(data) != "ONE TWO\n" {
		t.Fatalf("multi-edit = %q", data)
	}
}

func TestSourceDeleteReverts(t *testing.T) {
	e, dir := newSourceToolTestEvolver(t)
	path := filepath.Join(dir, "obsolete.go")
	content := "package obsolete\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := callTool(t, e, "SourceDelete", map[string]any{"file": "obsolete.go", "reason": "removed"})
	if got.isError {
		t.Fatalf("delete failed: %s", got.text)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("delete left the file: %v", err)
	}
	var id int64
	if err := e.db.db.QueryRow(`SELECT id FROM loop_edits WHERE loop_id='loop' ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.applyRevertEdits(context.Background(), []revertEdit{{
		id: id, module: "module", file: "obsolete.go", old: content, new: "",
	}}, 1, "test"); err != nil {
		t.Fatalf("revert delete: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != content {
		t.Fatalf("revert delete = %q err=%v", data, err)
	}
}
