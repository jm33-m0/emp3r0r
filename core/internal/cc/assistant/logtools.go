package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const (
	// maxLogWindowBytes bounds how much of the log the tool reads from the end.
	maxLogWindowBytes = 256 << 10
	defaultLogLines   = 80
	maxLogLines       = 200
)

type readLogArgs struct {
	Lines int    `json:"lines"`
	Match string `json:"match"`
}

// readLog returns a bounded tail of the operator log, optionally filtered by a
// case-insensitive substring. Command, module, and agent output all land here,
// so the model can see what happened before deciding the next step.
func (rt *toolRuntime) readLog(_ context.Context, raw json.RawMessage) (any, error) {
	var args readLogArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	lines := args.Lines
	if lines <= 0 {
		lines = defaultLogLines
	}
	if lines > maxLogLines {
		lines = maxLogLines
	}

	path := live.EmpLogFile
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("operator log path is not configured")
	}
	text, truncated, err := tailFileText(path, maxLogWindowBytes)
	if err != nil {
		return nil, err
	}
	all := logLines(text, truncated)

	match := strings.ToLower(strings.TrimSpace(args.Match))
	if match != "" {
		filtered := make([]string, 0, len(all))
		for _, line := range all {
			if strings.Contains(strings.ToLower(line), match) {
				filtered = append(filtered, line)
			}
		}
		all = filtered
	}
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	out := make([]string, 0, len(all))
	for _, line := range all {
		line = strings.TrimRight(sanitize.SanitizeText(line), " \t\r")
		if line != "" {
			out = append(out, line)
		}
	}
	result := map[string]any{
		"path":      path,
		"lines":     out,
		"truncated": truncated,
	}
	if match != "" && len(out) == 0 {
		result["hint"] = "no line matched " + match + "; call read_log without match for the tail"
	}
	return result, nil
}

// tailFileText reads the last max bytes of path. The bool reports whether the
// read started mid-file.
func tailFileText(path string, max int64) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, fmt.Errorf("open log: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", false, fmt.Errorf("stat log: %w", err)
	}
	size := info.Size()
	start := int64(0)
	truncated := false
	if size > max {
		start = size - max
		truncated = true
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return "", false, fmt.Errorf("seek log: %w", err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return "", false, fmt.Errorf("read log: %w", err)
	}
	return strings.ToValidUTF8(string(data), ""), truncated, nil
}

// logLines splits a log window, drops the partial first line of a mid-file
// read, and removes trailing blank lines.
func logLines(text string, truncated bool) []string {
	lines := strings.Split(text, "\n")
	if truncated && len(lines) > 0 {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}
