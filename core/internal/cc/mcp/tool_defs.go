package mcp

import (
	"context"
	"encoding/json"
)

// Tool is one callable function and its implementation.
type Tool struct {
	Def ToolDef
	// ReadOnly marks a tool that only reads C2 state or job output. The server
	// advertises it as readOnlyHint.
	ReadOnly    bool
	Destructive bool
	Run         func(context.Context, json.RawMessage) (any, error)
}

// ToolDef is the JSON schema advertised to the MCP client.
type ToolDef struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

// FunctionDef describes one callable tool.
type FunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}
