// Package mcp serves the operator toolset over the Model Context Protocol, so
// an external agent (Claude Code, Codex, and other MCP clients) can drive
// emp3r0r through the operator toolset.
//
// The server is a presentation layer only. Every tool call ends in the
// operator API request the console would send, so the C2 still derives the
// operator identity from the WireGuard peer, audits the action, and enforces
// job ownership and operator locks.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ProtocolVersion is the MCP revision this server implements. A client that
	// asks for an unknown revision is answered with this one and decides
	// whether it can continue.
	ProtocolVersion = "2025-06-18"

	// maxRequestBytes bounds one inbound JSON-RPC message. Tool arguments are
	// module flags and job IDs, so this is generous.
	maxRequestBytes = 4 << 20
	// maxInFlight bounds concurrent tool calls. Every call holds a goroutine and
	// at most 4 MiB of arguments; an unbounded client can otherwise exhaust the
	// operator process.
	maxInFlight = 16
	// maxRequestIDBytes bounds the client-supplied JSON-RPC ID, which is also
	// used as the in-flight map key and echoed in the response.
	maxRequestIDBytes = 128
	// maxResultBytes bounds one tool result before it is wrapped in MCP
	// content, keeping a single read from flooding the client.
	maxResultBytes = 512 << 10

	// shutdownWait bounds how long Serve waits for in-flight tool calls after
	// stdin closes. A module run can outlive the client; the job continues on
	// the C2 either way.
	shutdownWait = 2 * time.Second
)

var errMessageTooLarge = errors.New("message exceeds size limit")

// ToolSet is the tool source served over MCP. *Toolset implements it.
type ToolSet interface {
	Definitions() []ToolDef
	Lookup(name string) (Tool, bool)
	Call(ctx context.Context, name string, args json.RawMessage) (any, error)
}

// Options configures a stdio server.
type Options struct {
	// Name and Version identify the server in initialize.
	Name    string
	Version string
	// Instructions is returned to the client as server guidance.
	Instructions string
	// Tools builds the current toolset. It is called per request because the
	// active target and the module registry can change between calls.
	Tools func() ToolSet
	// Logf receives protocol and tool errors. It must never write to stdout.
	Logf func(string)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations *annotations   `json:"annotations,omitempty"`
}

type annotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// server is one stdio connection.
type server struct {
	opts Options

	writeMu sync.Mutex
	enc     *json.Encoder

	mu          sync.Mutex
	initialized bool
	inflight    sync.Map
	inflightN   atomic.Int32
	wg          sync.WaitGroup
}

type message struct {
	line []byte
	err  error
}

// Serve runs the JSON-RPC loop until stdin closes or ctx is canceled.
func Serve(ctx context.Context, in io.Reader, out io.Writer, opts Options) error {
	if opts.Tools == nil {
		return fmt.Errorf("mcp: no tool provider")
	}
	if opts.Name == "" {
		opts.Name = "emp3r0r"
	}
	s := &server{
		opts: opts,
		enc:  json.NewEncoder(out),
	}

	lines := make(chan message)
	go readLoop(ctx, in, lines)

	for {
		select {
		case <-ctx.Done():
			s.cancelAll()
			s.wait()
			return nil
		case msg, ok := <-lines:
			if !ok {
				s.cancelAll()
				s.wait()
				return nil
			}
			if msg.err != nil {
				if errors.Is(msg.err, errMessageTooLarge) {
					s.writeError(nil, -32700, "parse error: message exceeds 4 MiB")
					continue
				}
				if errors.Is(msg.err, io.EOF) {
					// The client closed stdin: a normal shutdown.
					s.cancelAll()
					s.wait()
					return nil
				}
				s.logf("mcp: read: %v", msg.err)
				s.cancelAll()
				s.wait()
				return msg.err
			}
			s.dispatch(ctx, msg.line)
		}
	}
}

// readLoop decodes newline-delimited JSON. MCP stdio framing is one JSON
// object per line with no embedded newlines.
func readLoop(ctx context.Context, in io.Reader, lines chan<- message) {
	defer close(lines)
	r := bufio.NewReader(in)
	for {
		line, err := readMessage(r)
		select {
		case lines <- message{line: line, err: err}:
		case <-ctx.Done():
			return
		}
		// An oversized message was drained through its newline; keep the
		// connection and report the error.
		if err != nil && !errors.Is(err, errMessageTooLarge) {
			return
		}
	}
}

func readMessage(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	tooLarge := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLarge {
			if len(buf)+len(chunk) > maxRequestBytes {
				tooLarge = true
				buf = nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case err == nil:
			if tooLarge {
				return nil, errMessageTooLarge
			}
			return bytes.TrimSpace(buf), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if tooLarge {
				return nil, errMessageTooLarge
			}
			if len(bytes.TrimSpace(buf)) == 0 {
				return nil, io.EOF
			}
			return bytes.TrimSpace(buf), nil
		default:
			return nil, err
		}
	}
}

func (s *server) dispatch(parent context.Context, line []byte) {
	if len(line) == 0 {
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		s.writeError(nil, -32700, "parse error")
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		s.writeError(req.ID, -32600, "invalid request")
		return
	}

	// A message without an ID is a notification and is never answered.
	if len(req.ID) == 0 {
		s.notification(req)
		return
	}

	switch req.Method {
	case "initialize":
		s.initialize(req)
	case "ping":
		s.writeResult(req.ID, struct{}{})
	case "tools/list":
		if !s.ready(req.ID) {
			return
		}
		s.toolsList(req.ID)
	case "tools/call":
		if !s.ready(req.ID) {
			return
		}
		s.toolsCall(parent, req)
	default:
		s.writeError(req.ID, -32601, "method not found")
	}
}

func (s *server) notification(req request) {
	switch req.Method {
	case "notifications/initialized":
		// initialize already marked the connection ready; this is a no-op.
	case "notifications/cancelled":
		var params struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || len(params.RequestID) == 0 {
			return
		}
		s.mu.Lock()
		cancel, _ := s.inflight.Load(string(params.RequestID))
		s.mu.Unlock()
		if cancel != nil {
			cancel.(context.CancelFunc)()
		}
	}
}

func (s *server) initialize(req request) {
	version := ProtocolVersion
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(req.Params, &params); err == nil {
		switch params.ProtocolVersion {
		case "2024-11-05", "2025-03-26", ProtocolVersion:
			version = params.ProtocolVersion
		}
	}

	result := map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    s.opts.Name,
			"version": s.opts.Version,
		},
	}
	if s.opts.Instructions != "" {
		result["instructions"] = s.opts.Instructions
	}

	s.mu.Lock()
	s.initialized = true
	s.mu.Unlock()
	s.writeResult(req.ID, result)
}

func (s *server) ready(id json.RawMessage) bool {
	s.mu.Lock()
	ok := s.initialized
	s.mu.Unlock()
	if !ok {
		s.writeError(id, -32002, "server not initialized")
	}
	return ok
}

func (s *server) toolsList(id json.RawMessage) {
	tools := s.opts.Tools()
	defs := tools.Definitions()
	out := make([]toolDefinition, 0, len(defs)+1)
	for _, def := range defs {
		tool, _ := tools.Lookup(def.Function.Name)
		schema := def.Function.Parameters
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, toolDefinition{
			Name:        def.Function.Name,
			Description: def.Function.Description,
			InputSchema: schema,
			Annotations: toolAnnotations(tool.ReadOnly, tool.Destructive),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	s.writeResult(id, map[string]any{"tools": out})
}

func (s *server) toolsCall(parent context.Context, req request) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
		s.writeError(req.ID, -32602, "invalid tools/call parameters")
		return
	}
	name := strings.TrimSpace(params.Name)
	if _, ok := s.opts.Tools().Lookup(name); !ok {
		s.writeError(req.ID, -32602, "unknown tool: "+name)
		return
	}

	key := string(req.ID)
	if len(key) > maxRequestIDBytes {
		s.writeError(req.ID, -32602, "request id is too long")
		return
	}
	ctx, cancel := context.WithCancel(parent)
	if _, loaded := s.inflight.LoadOrStore(key, cancel); loaded {
		cancel()
		s.writeError(req.ID, -32602, "duplicate request id")
		return
	}
	if s.inflightN.Add(1) > maxInFlight {
		s.inflight.Delete(key)
		s.inflightN.Add(-1)
		cancel()
		s.writeError(req.ID, -32000, "too many in-flight requests")
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				s.logf("mcp: tool %s panicked: %v", name, r)
				s.writeResult(req.ID, errorResult("%s: internal error", name))
			}
			s.inflight.Delete(key)
			s.inflightN.Add(-1)
			cancel()
		}()
		s.logf("mcp: tools/call %s", name)
		s.writeResult(req.ID, s.callTool(ctx, name, params.Arguments))
	}()
}

func (s *server) callTool(ctx context.Context, name string, args json.RawMessage) callResult {
	if len(bytes.TrimSpace(args)) == 0 {
		args = json.RawMessage("{}")
	}
	if !json.Valid(args) {
		return errorResult("%s: arguments are not valid JSON", name)
	}
	out, err := s.opts.Tools().Call(ctx, name, args)
	if err != nil {
		return errorResult("%s: %v", name, err)
	}
	return marshalResult(out)
}

func (s *server) writeResult(id json.RawMessage, result any) {
	s.write(response{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *server) writeError(id json.RawMessage, code int, msg string) {
	// JSON-RPC requires an explicit null id when the request could not be
	// parsed, so clients can still correlate the error.
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	s.write(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func (s *server) write(resp response) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.enc.Encode(resp); err != nil {
		s.logf("mcp: write: %v", err)
	}
}

func (s *server) cancelAll() {
	s.inflight.Range(func(_, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		return true
	})
}

func (s *server) wait() {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownWait):
	}
}

func (s *server) logf(format string, a ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(fmt.Sprintf(format, a...))
	}
}

func toolAnnotations(readOnly, destructive bool) *annotations {
	yes, no := true, false
	if readOnly {
		return &annotations{ReadOnlyHint: &yes, DestructiveHint: &no, OpenWorldHint: &yes}
	}
	if destructive {
		return &annotations{ReadOnlyHint: &no, DestructiveHint: &yes, OpenWorldHint: &yes}
	}
	return &annotations{ReadOnlyHint: &no, DestructiveHint: &no, OpenWorldHint: &yes}
}

func marshalResult(out any) callResult {
	b, err := json.Marshal(out)
	if err != nil {
		return errorResult("encode result: %v", err)
	}
	if len(b) > maxResultBytes {
		return errorResult("result is %d bytes, above the %d-byte limit; narrow the request", len(b), maxResultBytes)
	}
	return callResult{Content: []textContent{{Type: "text", Text: string(b)}}}
}

func errorResult(format string, a ...any) callResult {
	return callResult{
		Content: []textContent{{Type: "text", Text: fmt.Sprintf(format, a...)}},
		IsError: true,
	}
}
