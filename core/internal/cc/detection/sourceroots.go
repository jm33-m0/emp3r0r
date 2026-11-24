package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, dir, ok := strings.Cut(item, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		dir = strings.TrimSpace(dir)
		if !ok {
			// A bare name selects the installed producer module.
			installed, exists := DefaultProducerDirs()[name]
			if !exists {
				return nil, fmt.Errorf("producer %q is not installed; pass name=dir", name)
			}
			out[name] = installed
			continue
		}
		if name == "" || dir == "" {
			return nil, fmt.Errorf("producer entries must be name=dir, got %q", item)
		}
		out[name] = dir
	}
	return out, nil
}

// DefaultProducerDirs returns the installed shellcode-producer modules. The
// loop exposes them for editing and for BuildShellcode.
func DefaultProducerDirs() map[string]string {
	return producerDirsFor("donut", "crystal_pack")
}

// DefaultLinuxProducerDirs returns the installed Linux shellcode producer. The
// C agent is built as a shared object and wrapped by malasada.
func DefaultLinuxProducerDirs() map[string]string {
	return producerDirsFor("malasada")
}

// LinuxProducerDir returns the shipped malasada module for a source checkout
// or an installed operator kit. It is resolved from the module, never from a
// --producer path.
func LinuxProducerDir(moduleDir string) string {
	if dir := DefaultLinuxProducerDirs()["malasada"]; dir != "" {
		return dir
	}
	if strings.TrimSpace(moduleDir) == "" {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(filepath.Clean(moduleDir)), "malasada")
	if info, err := os.Stat(filepath.Join(candidate, "config.json")); err == nil && info.Mode().IsRegular() {
		return candidate
	}
	return ""
}

func producerDirsFor(names ...string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		if mod, ok := def.GetModule(name); ok && mod != nil && strings.TrimSpace(mod.Path) != "" {
			out[name] = mod.Path
		}
	}
	return out
}

// DefaultReadRoots returns the shared build inputs a module links but does not
// own. They are read-only source roots for the model. A Linux loop edits the
// whole C agent tree as a writable root, so it does not list its subdirectories
// here.
func DefaultReadRoots(moduleDir string) []string {
	parent := filepath.Dir(moduleDir)
	root := filepath.Dir(parent)
	dirs := []string{filepath.Join(parent, "common")}
	if !strings.EqualFold(filepath.Base(moduleDir), "stager_linux") {
		dirs = append(dirs,
			filepath.Join(root, "c_agent", "src", "util"),
			filepath.Join(root, "c_agent", "include", "util"),
		)
	}
	var roots []string
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			roots = append(roots, dir)
		}
	}
	return roots
}

// DefaultAgentSourceDir returns the C agent tree next to a module directory.
// The repository keeps core/modules/stager_linux and core/c_agent as siblings,
// and the installed operator kit preserves the same layout.
func DefaultAgentSourceDir(moduleDir string) string {
	modules := filepath.Dir(filepath.Clean(moduleDir))
	return filepath.Join(filepath.Dir(modules), "c_agent")
}

// DefaultGoAgentSourceDir returns the editable Go agent tree next to a module
// directory. The workspace and installed kit both keep modules/ and go_agent/
// as siblings.
func DefaultGoAgentSourceDir(moduleDir string) string {
	modules := filepath.Dir(filepath.Clean(moduleDir))
	return filepath.Join(filepath.Dir(modules), "go_agent")
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
	supplied = strings.TrimSpace(strings.ReplaceAll(supplied, "\\", "/"))
	name = strings.ToLower(strings.TrimSpace(name))
	if prefix, rest, ok := strings.Cut(supplied, "/"); ok {
		prefix = strings.ToLower(prefix)
		if _, exists := s.roots[prefix]; exists && (name == "" || name == prefix) {
			name, supplied = prefix, rest
		}
	}
	root, err := s.pick(name)
	if err != nil {
		return sourceRoot{}, "", err
	}
	path, err := analystPath(root.Dir, supplied)
	if err != nil {
		return sourceRoot{}, "", fmt.Errorf("%w; %s", err, s.rootHint(root))
	}
	return root, path, nil
}

// rootHint explains a path failure without dumping the root's contents.
func (s *sourceRoots) rootHint(root sourceRoot) string {
	return fmt.Sprintf("paths are relative to root %q; call SourceList to list files (roots: %s)",
		root.Name, s.describe())
}

// sourceSniffBytes is the prefix checked for NUL bytes before a file is
// treated as source text.
const sourceSniffBytes = 8 << 10

// maxSourceDirEntries bounds a directory listing returned by SourceRead.
const maxSourceDirEntries = 200

// readBoundedSource reads one source file without loading more than the
// per-file budget. Any text file under the root is readable; a binary prefix
// is rejected so a read cannot pull build artifacts into the model context.
func readBoundedSource(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", filepath.Base(path))
	}
	head := make([]byte, sourceSniffBytes)
	n, err := io.ReadFull(file, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	head = head[:n]
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, fmt.Errorf("%s is a binary file", filepath.Base(path))
	}
	rest, err := io.ReadAll(io.LimitReader(file, maxSourceFileBytes+1-int64(n)))
	if err != nil {
		return nil, err
	}
	data := append(head, rest...)
	if len(data) > maxSourceFileBytes {
		return nil, fmt.Errorf("%s exceeds the read bound", filepath.Base(path))
	}
	return data, nil
}

// listSourceDirectory returns a bounded entry list for a SourceRead directory.
// The model gets the names it can descend into without the tool failing on a
// path it already discovered with SourceList or a rejected guess.
func listSourceDirectory(rootDir, path string) (string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootDir, path)
	if err != nil {
		rel = "."
	}
	rel = filepath.ToSlash(rel)
	var b strings.Builder
	fmt.Fprintf(&b, "directory %s (%d entries)\n", rel, len(entries))
	for i, entry := range entries {
		if i >= maxSourceDirEntries {
			fmt.Fprintf(&b, "... %d more entries; use SourceList to list the whole root\n", len(entries)-maxSourceDirEntries)
			break
		}
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		b.WriteString(name)
		b.WriteByte('\n')
	}
	return b.String(), nil
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
// module; producers, agent sources, and read-only dependencies are addressed
// by name.
func moduleListTool(trees *sourceRoots) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceList",
		Description: "List source files in one root. Defaults to the payload module. " +
			"Set module to a producer (donut, crystal_pack), an agent source (c_agent, go_agent), or a configured read-only dependency.",
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

func moduleReadTool(trees *sourceRoots, tracker *evolver) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "SourceRead",
		Description: "Read one source file from a root, optionally a line range. " +
			"Use module to read a producer, an agent source (c_agent, go_agent), or a configured dependency; edits are still limited to writable roots.",
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
			info, err := os.Stat(path)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
			}
			if info.IsDir() {
				listing, err := listSourceDirectory(root.Dir, path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("list %s: %v", args.Path, err)), nil
				}
				if root.Name != trees.def {
					return tool.Text(fmt.Sprintf("# %s\n%s", root.Name, listing)), nil
				}
				return tool.Text(listing), nil
			}
			data, err := readBoundedSource(path)
			if err != nil {
				return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
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
			if tracker != nil && strings.EqualFold(root.Name, "crystal_pack") {
				rel := strings.TrimPrefix(strings.ReplaceAll(args.Path, "\\", "/"), "crystal_pack/")
				tracker.producerReads.Store(root.Name+"|"+strings.ToLower(rel), struct{}{})
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
			"use module for a producer, an agent source (c_agent, go_agent), or a configured dependency.",
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
				info, err := os.Stat(path)
				if err != nil {
					return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
				}
				if info.IsDir() {
					rel, err := filepath.Rel(root.Dir, path)
					if err != nil {
						return tool.Errorf(fmt.Sprintf("resolve %s: %v", args.Path, err)), nil
					}
					prefix := filepath.ToSlash(rel)
					if prefix == "." {
						prefix = ""
					} else {
						prefix = strings.TrimSuffix(prefix, "/") + "/"
					}
					scoped := make([]sourceFile, 0, len(files))
					for _, file := range files {
						if prefix == "" || strings.HasPrefix(file.rel, prefix) {
							scoped = append(scoped, file)
						}
					}
					if len(scoped) == 0 {
						return tool.Text(fmt.Sprintf("no source files under %s", args.Path)), nil
					}
					files = scoped
				} else {
					data, err := readBoundedSource(path)
					if err != nil {
						return tool.Errorf(fmt.Sprintf("read %s: %v", args.Path, err)), nil
					}
					rel, _ := filepath.Rel(root.Dir, path)
					files = []sourceFile{{rel: filepath.ToSlash(rel), lines: strings.Split(string(data), "\n")}}
				}
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
