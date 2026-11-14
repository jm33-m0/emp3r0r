package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/tool"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// ParseProducerDirs turns repeated name=dir entries into a producer map. The
// list is a CLI/MCP surface, so validation happens before the loop starts.
func ParseProducerDirs(entries []string) (map[string]string, error) {
	out := make(map[string]string, len(entries))
	for _, item := range entries {
		name, dir, ok := strings.Cut(item, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		dir = strings.TrimSpace(dir)
		if !ok || name == "" || dir == "" {
			return nil, fmt.Errorf("producer entries must be name=dir, got %q", item)
		}
		out[name] = dir
	}
	return out, nil
}

// DefaultProducerDirs returns the installed shellcode-producer modules. The
// loop exposes them for editing and for BuildShellcode.
func DefaultProducerDirs() map[string]string {
	out := map[string]string{}
	for _, name := range []string{"donut", "crystal_pack"} {
		if mod, ok := def.GetModule(name); ok && mod != nil && strings.TrimSpace(mod.Path) != "" {
			out[name] = mod.Path
		}
	}
	return out
}

// DefaultReadRoots returns the shared build inputs a module links but does not
// own. They are read-only source roots for the model.
func DefaultReadRoots(moduleDir string) []string {
	parent := filepath.Dir(moduleDir)
	root := filepath.Dir(parent)
	var roots []string
	for _, dir := range []string{
		filepath.Join(parent, "common"),
		filepath.Join(root, "c_agent", "src", "util"),
		filepath.Join(root, "c_agent", "include", "util"),
	} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			roots = append(roots, dir)
		}
	}
	return roots
}

// sourceRoot is one directory the detection agent may read. Writable roots are
// module directories the agent may edit; read-only roots are shared build
// inputs such as modules/common.
type sourceRoot struct {
	Name     string
	Dir      string
	Writable bool
}

var sourceRootName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// sourceRoots resolves the named roots the source tools expose.
type sourceRoots struct {
	def   string
	names []string
	roots map[string]sourceRoot
}

func newSingleRoot(dir string) *sourceRoots {
	roots, err := newSourceRoots("module", sourceRoot{Name: "module", Dir: dir, Writable: true})
	if err != nil {
		return &sourceRoots{def: "module", roots: map[string]sourceRoot{}}
	}
	return roots
}

// newSourceRoots validates and indexes the roots. Names are unique, lowercase,
// and the directories must exist. Symlinks are resolved once so every later
// path check compares real paths.
func newSourceRoots(def string, roots ...sourceRoot) (*sourceRoots, error) {
	out := &sourceRoots{def: def, roots: map[string]sourceRoot{}}
	for _, root := range roots {
		name := strings.ToLower(strings.TrimSpace(root.Name))
		if !sourceRootName.MatchString(name) {
			return nil, fmt.Errorf("invalid source root name %q", root.Name)
		}
		if _, exists := out.roots[name]; exists {
			return nil, fmt.Errorf("duplicate source root %q", name)
		}
		dir, err := filepath.Abs(strings.TrimSpace(root.Dir))
		if err != nil {
			return nil, fmt.Errorf("resolve source root %s: %w", name, err)
		}
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, fmt.Errorf("resolve source root %s: %w", name, err)
		}
		info, err := os.Stat(real)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("source root %s is not a directory: %s", name, dir)
		}
		out.roots[name] = sourceRoot{Name: name, Dir: real, Writable: root.Writable}
		out.names = append(out.names, name)
	}
	slices.Sort(out.names)
	if _, ok := out.roots[out.def]; !ok && len(out.names) > 0 {
		out.def = out.names[0]
	}
	return out, nil
}

func (s *sourceRoots) pick(name string) (sourceRoot, error) {
	if s == nil || len(s.roots) == 0 {
		return sourceRoot{}, fmt.Errorf("no source roots are configured")
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = s.def
	}
	root, ok := s.roots[name]
	if !ok {
		return sourceRoot{}, fmt.Errorf("unknown source root %q; available: %s", name, strings.Join(s.names, ", "))
	}
	return root, nil
}

func (s *sourceRoots) resolve(name, supplied string) (sourceRoot, string, error) {
	root, err := s.pick(name)
	if err != nil {
		return sourceRoot{}, "", err
	}
	path, err := analystPath(root.Dir, supplied)
	if err != nil {
		return sourceRoot{}, "", err
	}
	return root, path, nil
}

func (s *sourceRoots) describe() string {
	if s == nil {
		return ""
	}
	parts := make([]string, 0, len(s.names))
	for _, name := range s.names {
		root := s.roots[name]
		mode := "read"
		if root.Writable {
			mode = "edit"
		}
		parts = append(parts, fmt.Sprintf("%s=%s (%s)", name, root.Dir, mode))
	}
	return strings.Join(parts, "; ")
}

// moduleListTool lists one root. With no module argument it lists the payload
// module; producer modules and read-only dependencies are addressed by name.
func moduleListTool(trees *sourceRoots) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceList",
		Description: "List source files in one root. Defaults to the payload module. " +
			"Set module to a producer module (donut, crystal_pack) or a configured read-only dependency.",
		Prompt: "List module source files.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module": map[string]any{"type": "string", "description": "Source root name; default: the payload module."},
			},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module string `json:"module"`
			}
			_ = json.Unmarshal(raw, &args)
			root, err := trees.pick(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			index := newSourceIndex(root.Dir)
			names := make([]string, 0, len(index.files))
			for _, file := range index.files {
				names = append(names, file.rel)
			}
			return tool.Text(strings.Join(names, "\n")), nil
		},
	})
}

func moduleReadTool(trees *sourceRoots) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceRead",
		Description: "Read one source file from a root, optionally a line range. " +
			"Use module to read a producer module or a configured dependency; edits are still limited to writable roots.",
		Prompt: "Read a module source file.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module":     map[string]any{"type": "string", "description": "Source root name; default: the payload module."},
				"path":       analystSchemaPath,
				"start_line": map[string]any{"type": "integer", "description": "First line, 1-based."},
				"end_line":   map[string]any{"type": "integer", "description": "Last line, inclusive."},
			},
			"required": []string{"path"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module    string `json:"module"`
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			root, path, err := trees.resolve(args.Module, args.Path)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
			}
			if len(data) > maxSourceFileBytes {
				return tool.Errorf(fmt.Sprintf("%s exceeds the read bound", args.Path)), nil
			}
			lines := strings.Split(string(data), "\n")
			start := args.StartLine
			if start <= 0 {
				start = 1
			}
			end := args.EndLine
			if end <= 0 || end > len(lines) {
				end = len(lines)
			}
			if end < start {
				return tool.Errorf("end_line is before start_line"), nil
			}
			if end-start+1 > maxAnalystReadLines {
				end = start + maxAnalystReadLines - 1
			}
			var b strings.Builder
			for lineNo := start; lineNo <= end && lineNo <= len(lines); lineNo++ {
				fmt.Fprintf(&b, "%d: %s\n", lineNo, clipUTF8(lines[lineNo-1], 400))
			}
			if root.Name != trees.def {
				return tool.Text(fmt.Sprintf("# %s\n%s", root.Name, b.String())), nil
			}
			return tool.Text(b.String()), nil
		},
	})
}

func moduleSearchTool(trees *sourceRoots) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceSearch",
		Description: "Search one source root with a regular expression. Defaults to the payload module; " +
			"use module for a producer module or a configured dependency.",
		Prompt: "Search module source.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"module":  map[string]any{"type": "string", "description": "Source root name; default: the payload module."},
				"pattern": map[string]any{"type": "string", "description": "Go regular expression."},
				"path":    map[string]any{"type": "string", "description": "Optional file to search; default all source files."},
			},
			"required": []string{"pattern"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, raw json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var args struct {
				Module  string `json:"module"`
				Pattern string `json:"pattern"`
				Path    string `json:"path"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return tool.Errorf("invalid arguments"), nil
			}
			if len(args.Pattern) > 200 {
				return tool.Errorf("pattern is too long"), nil
			}
			re, err := regexp.Compile(args.Pattern)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("invalid pattern: %v", err)), nil
			}
			root, err := trees.pick(args.Module)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("%v", err)), nil
			}
			files := newSourceIndex(root.Dir).files
			if args.Path != "" {
				_, path, err := trees.resolve(args.Module, args.Path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("%v", err)), nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
				}
				rel, _ := filepath.Rel(root.Dir, path)
				files = []sourceFile{{rel: filepath.ToSlash(rel), lines: strings.Split(string(data), "\n")}}
			}
			var b strings.Builder
			hits := 0
			for _, file := range files {
				for lineNo, line := range file.lines {
					if !re.MatchString(line) {
						continue
					}
					hits++
					fmt.Fprintf(&b, "%s:%d: %s\n", file.rel, lineNo+1, clipUTF8(strings.TrimSpace(line), 300))
					if hits >= maxAnalystHits {
						return tool.Text(b.String()), nil
					}
				}
			}
			if hits == 0 {
				return tool.Text("no match"), nil
			}
			return tool.Text(b.String()), nil
		},
	})
}
