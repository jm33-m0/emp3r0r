package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// readToolset is the read-only tool registry for one target.
type readToolset struct {
	tools map[string]Tool
}

// newReadToolset builds the read-only tools for target.
func newReadToolset(target *def.Emp3r0rAgent) *readToolset {
	return &readToolset{tools: buildReadTools(&toolRuntime{target: target})}
}

// Definitions returns the tool schemas in name order.
func (t *readToolset) Definitions() []ToolDef {
	return toolDefs(t.tools)
}

// Lookup returns one tool by name.
func (t *readToolset) Lookup(name string) (Tool, bool) {
	tool, ok := t.tools[name]
	return tool, ok
}

// Call runs one tool. A tool error is returned to the caller, which decides
// whether it is a protocol error or a tool result with isError set.
func (t *readToolset) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	tool, ok := t.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	return tool.Run(ctx, args)
}

func toolDefs(tools map[string]Tool) []ToolDef {
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	defs := make([]ToolDef, 0, len(names))
	for _, name := range names {
		defs = append(defs, tools[name].Def)
	}
	return defs
}
