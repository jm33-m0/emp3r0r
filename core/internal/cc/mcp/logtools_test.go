package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

func writeTestLog(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "emp3r0r.log")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := live.EmpLogFile
	live.EmpLogFile = path
	t.Cleanup(func() { live.EmpLogFile = prev })
}

func TestReadLogTailAndMatch(t *testing.T) {
	writeTestLog(t, "line one\nline two ERROR\nline three\nline four ERROR\n")
	rt := &toolRuntime{}

	out, err := rt.readLog(context.Background(), json.RawMessage(`{"lines":2}`))
	if err != nil {
		t.Fatal(err)
	}
	lines := out.(map[string]any)["lines"].([]string)
	if len(lines) != 2 || lines[0] != "line three" || lines[1] != "line four ERROR" {
		t.Fatalf("tail = %#v", lines)
	}

	out, err = rt.readLog(context.Background(), json.RawMessage(`{"lines":1,"match":"error"}`))
	if err != nil {
		t.Fatal(err)
	}
	lines = out.(map[string]any)["lines"].([]string)
	if len(lines) != 1 || lines[0] != "line four ERROR" {
		t.Fatalf("match = %#v", lines)
	}
}

func TestReadLogMissingFile(t *testing.T) {
	prev := live.EmpLogFile
	live.EmpLogFile = filepath.Join(t.TempDir(), "absent.log")
	t.Cleanup(func() { live.EmpLogFile = prev })

	rt := &toolRuntime{}
	if _, err := rt.readLog(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected an error for a missing log")
	}
}
