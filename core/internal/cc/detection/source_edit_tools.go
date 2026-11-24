package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const maxMultiEditText = 16 << 10

// sourceWriteTool creates or replaces a whole source file. It exists because
// the editor's exact-string EditSource is a poor fit for a new package file or
// a deliberate rewrite, and because parent directories must be creatable for
// multi-file refactors.
func (e *evolver) sourceWriteTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceWrite",
		Description: "Write a complete source file, creating missing parent directories. Existing files are overwritten atomically; " +
			"the previous content is recorded so a failed or offline cycle can restore it. Use EditSource for a small targeted change, " +
			"SourceMultiEdit for several replacements in one file, and SourceDelete to remove a file.",
		Prompt: "Write the whole file when creating it or replacing most of it.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module":  map[string]any{"type": "string", "description": "Writable source root; default: the payload module."},
				"file":    map[string]any{"type": "string", "description": "Path relative to the root. Parent directories are created."},
				"content": map[string]any{"type": "string", "description": "Complete new file content. Must not be empty when overwriting a non-empty file; use SourceDelete."},
				"reason":  map[string]any{"type": "string", "description": "Why this write removes the finding."},
			},
			"required": []string{"file", "content"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module  string `json:"module"`
				File    string `json:"file"`
				Content string `json:"content"`
				Reason  string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.usedCycles() >= e.cfg.Iterations {
				return tool.Errorf("iteration limit reached; the write could not be built or tested"), nil
			}
			root, err := e.root(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if !root.Writable {
				return tool.Errorf(fmt.Sprintf("source root %s is read-only", root.Name)), nil
			}
			if err := e.requireProducerContract(root.Name, args.File); err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if len(args.Content) > maxSourceFileBytes {
				return tool.Errorf(fmt.Sprintf("content exceeds the %d byte source bound", maxSourceFileBytes)), nil
			}
			result, err := e.applySourceWrite(ctx, root, args.File, args.Content, args.Reason)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(result)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) applySourceWrite(ctx context.Context, root sourceRoot, file, content, reason string) (editResult, error) {
	file = sourceRelativeFile(root, file)
	path, err := analystPath(root.Dir, file)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return editResult{}, fmt.Errorf("stat %s: %w", file, statErr)
		}
		if !info.Mode().IsRegular() {
			return editResult{}, fmt.Errorf("%s is not a regular file", file)
		}
		original, readErr := os.ReadFile(path)
		if readErr != nil {
			return editResult{}, fmt.Errorf("read %s: %w", file, readErr)
		}
		if len(original) == 0 {
			return editResult{}, fmt.Errorf("%s exists and is empty; use EditSource to insert content", file)
		}
		if string(original) == content {
			return editResult{}, fmt.Errorf("%s content is unchanged", file)
		}
		if content == "" {
			return editResult{}, fmt.Errorf("refusing to empty %s; use SourceDelete", file)
		}
		if token := introducesForbiddenLoaderMechanism(string(original), content); token != "" {
			return editResult{}, fmt.Errorf("refusing to introduce %s: a memfd is a named kernel object and an explicit detection signal, not an evasion win", token)
		}
		if strings.EqualFold(filepath.Base(path), "config.json") {
			if err := guardModuleConfig(string(original), content); err != nil {
				return editResult{}, err
			}
		}
		if err := writeFileAtomic(path, []byte(content), info.Mode().Perm()); err != nil {
			return editResult{}, fmt.Errorf("write %s: %w", file, err)
		}
		return e.recordSourceEdit(ctx, root, file, string(original), content, reason, false,
			sourceWrite{Updated: content, Line: 1, Path: path, Original: original})
	}
	if !errors.Is(err, os.ErrNotExist) {
		return editResult{}, err
	}
	if token := introducesForbiddenLoaderMechanism("", content); token != "" {
		return editResult{}, fmt.Errorf("refusing to introduce %s: a memfd is a named kernel object and an explicit detection signal, not an evasion win", token)
	}
	updated, err := createSourceFileWithDirs(root, file, content)
	if err != nil {
		return editResult{}, err
	}
	return e.recordSourceEdit(ctx, root, file, "", content, reason, true, updated)
}

// sourceMultiEditTool applies several exact replacements to one file
// atomically, mirroring the MultiEdit tool in Norma's generic harness.
func (e *evolver) sourceMultiEditTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceMultiEdit",
		Description: "Apply several exact string replacements to one source file in one atomic operation. " +
			"Edits run in order against the in-memory content; if any old_string is missing or not unique without replace_all, nothing is written. " +
			"Use this instead of several EditSource calls on the same file.",
		Prompt: "Apply all replacements for one file in one call.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module": map[string]any{"type": "string", "description": "Writable source root; default: the payload module."},
				"file":   map[string]any{"type": "string", "description": "Path relative to the root."},
				"edits": map[string]any{
					"type":        "array",
					"description": "Edits to apply in order.",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"old_string":  map[string]any{"type": "string", "description": "Exact text to replace."},
							"new_string":  map[string]any{"type": "string", "description": "Replacement text."},
							"replace_all": map[string]any{"type": "boolean", "description": "Replace every occurrence."},
						},
						"required": []string{"old_string", "new_string"},
					},
				},
				"reason": map[string]any{"type": "string", "description": "Why these edits remove the finding."},
			},
			"required": []string{"file", "edits"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module string       `json:"module"`
				File   string       `json:"file"`
				Edits  []sourceEdit `json:"edits"`
				Reason string       `json:"reason"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if len(args.Edits) == 0 {
				return tool.Errorf("edits must contain at least one replacement"), nil
			}
			if e.usedCycles() >= e.cfg.Iterations {
				return tool.Errorf("iteration limit reached; the edits could not be built or tested"), nil
			}
			root, err := e.root(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if !root.Writable {
				return tool.Errorf(fmt.Sprintf("source root %s is read-only", root.Name)), nil
			}
			if err := e.requireProducerContract(root.Name, args.File); err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			result, err := e.applyMultiEdit(ctx, root, args.File, args.Edits, args.Reason)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(result)
			return tool.Text(string(data)), nil
		},
	})
}

type sourceEdit struct {
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
}

func (e *evolver) applyMultiEdit(ctx context.Context, root sourceRoot, file string, edits []sourceEdit, reason string) (editResult, error) {
	file = sourceRelativeFile(root, file)
	path, err := analystPath(root.Dir, file)
	if err != nil {
		return editResult{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return editResult{}, fmt.Errorf("read %s: %w", file, err)
	}
	if len(data) == 0 {
		return editResult{}, fmt.Errorf("%s is empty; use SourceWrite", file)
	}
	original := string(data)
	content := original
	for i, edit := range edits {
		if edit.OldString == "" {
			return editResult{}, fmt.Errorf("edit %d: old_string is required", i+1)
		}
		if edit.OldString == edit.NewString {
			return editResult{}, fmt.Errorf("edit %d: old_string and new_string are identical", i+1)
		}
		if len(edit.OldString) > maxMultiEditText || len(edit.NewString) > maxMultiEditText {
			return editResult{}, fmt.Errorf("edit %d exceeds 16 KiB", i+1)
		}
		count := strings.Count(content, edit.OldString)
		if count == 0 {
			return editResult{}, fmt.Errorf("edit %d: old_string not found after the preceding edits", i+1)
		}
		if count > 1 && !edit.ReplaceAll {
			return editResult{}, fmt.Errorf("edit %d: old_string is not unique (%d matches); add context or set replace_all", i+1, count)
		}
		if token := introducesForbiddenLoaderMechanism(edit.OldString, edit.NewString); token != "" {
			return editResult{}, fmt.Errorf("edit %d: refusing to introduce %s", i+1, token)
		}
		if edit.ReplaceAll {
			content = strings.ReplaceAll(content, edit.OldString, edit.NewString)
		} else {
			content = strings.Replace(content, edit.OldString, edit.NewString, 1)
		}
	}
	if content == "" {
		return editResult{}, fmt.Errorf("refusing to empty %s; use SourceDelete", file)
	}
	if len(content) > maxSourceFileBytes {
		return editResult{}, fmt.Errorf("result exceeds the %d byte source bound", maxSourceFileBytes)
	}
	if strings.EqualFold(filepath.Base(path), "config.json") {
		if err := guardModuleConfig(original, content); err != nil {
			return editResult{}, err
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return editResult{}, fmt.Errorf("stat %s: %w", file, err)
	}
	if err := writeFileAtomic(path, []byte(content), info.Mode().Perm()); err != nil {
		return editResult{}, fmt.Errorf("write %s: %w", file, err)
	}
	return e.recordSourceEdit(ctx, root, file, original, content, reason, false,
		sourceWrite{Updated: content, Line: 1, Path: path, Original: data})
}

// sourceDeleteTool removes one source file. The content is recorded so a
// restore can recreate it.
func (e *evolver) sourceDeleteTool() tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceDelete",
		Description: "Delete one source file. The full previous content is recorded so a failed or offline cycle can restore it. " +
			"An empty file cannot be deleted; there is nothing to restore.",
		Prompt: "Delete a file that is no longer part of the design.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module": map[string]any{"type": "string", "description": "Writable source root; default: the payload module."},
				"file":   map[string]any{"type": "string", "description": "Path relative to the root."},
				"reason": map[string]any{"type": "string", "description": "Why removing this file removes the finding."},
			},
			"required": []string{"file"},
		},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module string `json:"module"`
				File   string `json:"file"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if e.usedCycles() >= e.cfg.Iterations {
				return tool.Errorf("iteration limit reached; the delete could not be built or tested"), nil
			}
			root, err := e.root(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			if !root.Writable {
				return tool.Errorf(fmt.Sprintf("source root %s is read-only", root.Name)), nil
			}
			if err := e.requireProducerContract(root.Name, args.File); err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			result, err := e.applySourceDelete(ctx, root, args.File, args.Reason)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, _ := json.Marshal(result)
			return tool.Text(string(data)), nil
		},
	})
}

func (e *evolver) applySourceDelete(ctx context.Context, root sourceRoot, file, reason string) (editResult, error) {
	file = sourceRelativeFile(root, file)
	path, err := analystPath(root.Dir, file)
	if err != nil {
		return editResult{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return editResult{}, fmt.Errorf("stat %s: %w", file, err)
	}
	if !info.Mode().IsRegular() {
		return editResult{}, fmt.Errorf("%s is not a regular file", file)
	}
	if strings.EqualFold(filepath.Base(path), "config.json") {
		return editResult{}, fmt.Errorf("config.json is the module contract; edit it instead of deleting it")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return editResult{}, fmt.Errorf("read %s: %w", file, err)
	}
	if len(data) == 0 {
		return editResult{}, fmt.Errorf("%s is empty; there is nothing to restore", file)
	}
	if err := os.Remove(path); err != nil {
		return editResult{}, fmt.Errorf("delete %s: %w", file, err)
	}
	payloadID := int64(0)
	if e.last != nil {
		payloadID = e.last.PayloadID
	}
	if err := e.db.SaveEdit(ctx, EditRecord{
		LoopID: e.cfg.LoopID, Iteration: e.iter + 1, PayloadID: payloadID,
		Module: root.Name, File: file, Old: string(data), New: "", Reason: reason,
	}); err != nil {
		if restoreErr := os.WriteFile(path, data, info.Mode().Perm()); restoreErr != nil {
			return editResult{}, fmt.Errorf("save delete: %w (restore %s failed: %v)", err, file, restoreErr)
		}
		return editResult{}, fmt.Errorf("save delete: %w", err)
	}
	e.logClass(logging.ClassEdit, "%s/%s: deleted (%s)", root.Name, file, reason)
	if e.editTouchesAgentSource(root) {
		e.agentSourceDirty.Store(true)
	}
	return editResult{
		Module: root.Name, File: file, Line: 1, Bytes: 0, Reason: reason,
		Message: "file deleted; call DetectionCycle to rebuild and detonate",
	}, nil
}

// createSourceFileWithDirs creates a new file and any missing parent
// directories inside a writable root.
func createSourceFileWithDirs(root sourceRoot, file, content string) (sourceWrite, error) {
	if !root.Writable {
		return sourceWrite{}, fmt.Errorf("source root %s is read-only", root.Name)
	}
	path, err := newSourcePathWithDirs(root, file)
	if err != nil {
		return sourceWrite{}, err
	}
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return sourceWrite{}, fmt.Errorf("%s already exists; edit it instead", file)
		}
		return sourceWrite{}, fmt.Errorf("create %s: %w", file, err)
	}
	removeOnError := func(cause error) (sourceWrite, error) {
		_ = handle.Close()
		_ = os.Remove(path)
		return sourceWrite{}, cause
	}
	if _, err := handle.WriteString(content); err != nil {
		return removeOnError(fmt.Errorf("write %s: %w", file, err))
	}
	if err := handle.Sync(); err != nil {
		return removeOnError(fmt.Errorf("sync %s: %w", file, err))
	}
	if err := handle.Close(); err != nil {
		_ = os.Remove(path)
		return sourceWrite{}, fmt.Errorf("close %s: %w", file, err)
	}
	return sourceWrite{Updated: content, Line: 1, Path: path}, nil
}

// newSourcePathWithDirs resolves a new file inside the root and creates its
// missing parent directories. The nearest existing ancestor is resolved
// through symlinks and checked against the root before MkdirAll runs.
func newSourcePathWithDirs(root sourceRoot, file string) (string, error) {
	file = sourceRelativeFile(root, file)
	if file == "" || !analystSourcePath.MatchString(file) {
		return "", fmt.Errorf("invalid source path")
	}
	rootReal, err := filepath.EvalSymlinks(root.Dir)
	if err != nil {
		return "", fmt.Errorf("resolve module directory: %w", err)
	}
	clean := filepath.Clean(filepath.FromSlash(file))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("source path escapes the module directory")
	}
	parentRel := filepath.Dir(clean)
	ancestor := parentRel
	for {
		if _, statErr := os.Lstat(filepath.Join(rootReal, ancestor)); statErr == nil {
			break
		}
		next := filepath.Dir(ancestor)
		if ancestor == "." || next == ancestor {
			ancestor = "."
			break
		}
		ancestor = next
	}
	ancestorReal, err := filepath.EvalSymlinks(filepath.Join(rootReal, ancestor))
	if err != nil {
		return "", fmt.Errorf("resolve source directory: %w", err)
	}
	if rel, err := filepath.Rel(rootReal, ancestorReal); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("source path escapes the module directory")
	}
	parentPath := filepath.Join(rootReal, parentRel)
	if err := os.MkdirAll(parentPath, 0o755); err != nil {
		return "", fmt.Errorf("create parent directory: %w", err)
	}
	parentReal, err := filepath.EvalSymlinks(parentPath)
	if err != nil {
		return "", fmt.Errorf("resolve source directory: %w", err)
	}
	if rel, err := filepath.Rel(rootReal, parentReal); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("source path escapes the module directory")
	}
	path := filepath.Join(parentReal, filepath.Base(clean))
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("%s already exists; edit it instead", file)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat %s: %w", file, err)
	}
	return path, nil
}
