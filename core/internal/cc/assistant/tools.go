package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
)

const (
	maxModuleResults = 50
	maxJobResults    = 100
	maxReadBytes     = 256 << 10
	defaultReadBytes = 32 << 10
	maxTableRows     = 200
)

type toolRuntime struct {
	cfg    Config
	target *def.Emp3r0rAgent
}

func buildTools(rt *toolRuntime) map[string]Tool {
	tools := map[string]Tool{}

	tools["list_modules"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "list_modules",
				Description: "List modules whose platform and text match a query. Use this before naming a module.",
				Parameters: ObjectSchema(map[string]any{
					"query":    StringProp("Case-insensitive text matched against module name and description"),
					"platform": StringProp("Target OS: linux, windows, or any. Defaults to the selected target's OS."),
				}),
			},
		},
		ReadOnly: true,
		Run:      rt.listModules,
	}

	tools["module_help"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "module_help",
				Description: "Return one module's description, parameters, defaults, generated usage line, and examples.",
				Parameters: ObjectSchema(map[string]any{
					"name": StringProp("Exact module name"),
				}, "name"),
			},
		},
		ReadOnly: true,
		Run:      rt.moduleHelp,
	}

	tools["list_agents"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "list_agents",
				Description: "List agents visible to this operator with host, identity, OS, process, network, mesh, transport, privilege, and selected-target detail.",
				Parameters: ObjectSchema(map[string]any{
					"agent": StringProp("Optional agent tag; return only that agent"),
				}),
			},
		},
		ReadOnly: true,
		Run:      rt.listAgents,
	}

	tools["list_jobs"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "list_jobs",
				Description: "List recent jobs dispatched by this operator process, newest first.",
				Parameters: ObjectSchema(map[string]any{
					"limit": IntegerProp("Maximum rows, 1-100 (default 20)"),
					"agent": StringProp("Only jobs for this agent tag"),
				}),
			},
		},
		ReadOnly: true,
		Run:      rt.listJobs,
	}

	tools["read_job_output"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "read_job_output",
				Description: "Read a bounded slice of a job's raw output. Use result_summary first for parsed facts.",
				Parameters: ObjectSchema(map[string]any{
					"job_id": StringProp("Job UUID"),
					"offset": IntegerProp("Byte offset; ignored when tail is true"),
					"limit":  IntegerProp("Maximum bytes, 1-262144 (default 32768)"),
					"tail":   BooleanProp("Return the last limit bytes instead of a window from offset"),
				}, "job_id"),
			},
		},
		ReadOnly: true,
		Run:      rt.readJobOutput,
	}

	tools["result_summary"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "result_summary",
				Description: "Parse a job's output into deterministic facts: LDAP accounts, groups, trusts, ADCS templates and findings; process/list tables; or a text head/tail.",
				Parameters: ObjectSchema(map[string]any{
					"job_id": StringProp("Job UUID"),
				}, "job_id"),
			},
		},
		ReadOnly: true,
		Run:      rt.resultSummary,
	}

	tools["read_log"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "read_log",
				Description: "Read a bounded tail of the operator log (command, module, and agent output), optionally filtered by a case-insensitive substring. Use this to see what just happened before deciding the next step.",
				Parameters: ObjectSchema(map[string]any{
					"lines": IntegerProp("Maximum lines from the end, 1-200 (default 80)"),
					"match": StringProp("Optional case-insensitive substring filter"),
				}),
			},
		},
		ReadOnly: true,
		Run:      rt.readLog,
	}

	tools["review_command"] = Tool{
		Def: ToolDef{
			Type: "function",
			Function: FunctionDef{
				Name:        "review_command",
				Description: "Validate a module invocation or single-line shell command, render it, and compute its deterministic OPSEC review. Never executes anything.",
				Parameters: ObjectSchema(map[string]any{
					"module": StringProp("Exact module name; provide this or command, not both"),
					"flags": map[string]any{
						"type":                 "object",
						"description":          "Flag name to value. Boolean flags take true or false.",
						"additionalProperties": map[string]any{"type": "string"},
					},
					"command": StringProp("Single-line shell command to run through exec; provide this or module, not both"),
				}),
			},
		},
		ReadOnly: true,
		Run:      rt.reviewCommand,
	}

	return tools
}

// ObjectSchema builds the JSON schema for a tool's arguments. It is shared
// with the MCP tool definitions so both surfaces advertise the same shapes.
func ObjectSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// StringProp describes a string tool argument.
func StringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// IntegerProp describes an integer tool argument.
func IntegerProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// BooleanProp describes a boolean tool argument.
func BooleanProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

type listModulesArgs struct {
	Query    string `json:"query"`
	Platform string `json:"platform"`
}

type moduleRow struct {
	Name     string `json:"name"`
	Comment  string `json:"comment"`
	Platform string `json:"platform"`
	Type     string `json:"type"`
	Local    bool   `json:"local"`
}

func (rt *toolRuntime) listModules(_ context.Context, raw json.RawMessage) (any, error) {
	var args listModulesArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	platform := strings.ToLower(strings.TrimSpace(args.Platform))
	if platform == "" && rt.target != nil {
		platform = strings.ToLower(strings.TrimSpace(rt.target.GOOS))
	}
	if platform == "any" {
		platform = ""
	}
	query := strings.ToLower(strings.TrimSpace(args.Query))

	var rows []moduleRow
	var allNames []string
	def.ForEachModule(func(_ string, mod *def.ModuleConfig) {
		if mod == nil {
			return
		}
		p := strings.ToLower(strings.TrimSpace(mod.Platform))
		if platform != "" && p != "" && p != "generic" && p != platform {
			return
		}
		allNames = append(allNames, mod.Name)
		if query != "" {
			haystack := strings.ToLower(mod.Name + " " + mod.Comment + " " + mod.Help)
			if !strings.Contains(haystack, query) {
				return
			}
		}
		rows = append(rows, moduleRow{
			Name:     mod.Name,
			Comment:  sanitize.SanitizeText(mod.Comment),
			Platform: mod.Platform,
			Type:     mod.AgentConfig.Type,
			Local:    mod.IsLocal,
		})
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	total := len(rows)
	if len(rows) > maxModuleResults {
		rows = rows[:maxModuleResults]
	}
	result := map[string]any{
		"modules":   rows,
		"total":     total,
		"truncated": total > len(rows),
		"platform":  platform,
	}
	// An empty search tells the model nothing and invites another guess. Point
	// it at modules that do exist instead.
	if len(rows) == 0 && query != "" {
		sort.Strings(allNames)
		if len(allNames) > 20 {
			allNames = allNames[:20]
		}
		if len(allNames) == 0 {
			result["hint"] = "no modules are loaded for this platform; do not search again"
		} else {
			result["hint"] = "no match; available modules include: " + strings.Join(allNames, ", ")
		}
	}
	return result, nil
}

type moduleHelpArgs struct {
	Name string `json:"name"`
}

type paramInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"`
	Default     string   `json:"default"`
	Choices     []string `json:"choices,omitempty"`
	Required    bool     `json:"required"`
	Internal    bool     `json:"internal,omitempty"`
	ArgvFlag    string   `json:"argv_flag,omitempty"`
}

type moduleInfo struct {
	Name       string            `json:"name"`
	Comment    string            `json:"comment"`
	Platform   string            `json:"platform"`
	Type       string            `json:"type"`
	Local      bool              `json:"local"`
	Usage      string            `json:"usage"`
	Parameters []paramInfo       `json:"parameters"`
	Examples   []string          `json:"examples,omitempty"`
	Help       string            `json:"help,omitempty"`
	Opsec      *def.OpsecProfile `json:"opsec,omitempty"`
}

func (rt *toolRuntime) moduleHelp(_ context.Context, raw json.RawMessage) (any, error) {
	var args moduleHelpArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	name := strings.TrimSpace(args.Name)
	mod, ok := def.GetModule(name)
	if !ok {
		return nil, fmt.Errorf("module %q not found%s", name, similarModules(name))
	}
	return describeModule(mod), nil
}

// DescribeModule returns the same structure the module_help tool emits. The
// console uses it to pre-load context for `ask --module`.
func DescribeModule(name string) (any, error) {
	mod, ok := def.GetModule(strings.TrimSpace(name))
	if !ok {
		return nil, fmt.Errorf("module %q not found%s", name, similarModules(name))
	}
	return describeModule(mod), nil
}

func describeModule(mod *def.ModuleConfig) moduleInfo {
	names := make([]string, 0, len(mod.Options))
	for name := range mod.Options {
		names = append(names, name)
	}
	sort.Strings(names)
	params := make([]paramInfo, 0, len(names))
	for _, name := range names {
		opt := mod.Options[name]
		if opt == nil {
			continue
		}
		params = append(params, paramInfo{
			Name:        opt.Name,
			Description: sanitize.SanitizeText(opt.Desc),
			Type:        opt.Type,
			Default:     opt.Val,
			Choices:     opt.Vals,
			Required:    opt.Required,
			Internal:    opt.Internal,
			ArgvFlag:    opt.ArgvFlag,
		})
	}
	examples := make([]string, 0, len(mod.Examples))
	for _, ex := range mod.Examples {
		examples = append(examples, sanitize.SanitizeText(ex))
	}
	return moduleInfo{
		Name:       mod.Name,
		Comment:    sanitize.SanitizeText(mod.Comment),
		Platform:   mod.Platform,
		Type:       mod.AgentConfig.Type,
		Local:      mod.IsLocal,
		Usage:      usageLine(mod),
		Parameters: params,
		Examples:   examples,
		Help:       sanitize.SanitizeText(mod.Help),
		Opsec:      mod.Opsec,
	}
}

// usageLine renders the console invocation. Required options are shown with
// their default, optional ones in brackets, and internal options are omitted
// because the console never asks for them.
func usageLine(mod *def.ModuleConfig) string {
	names := make([]string, 0, len(mod.Options))
	for name := range mod.Options {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := []string{mod.Name}
	for _, name := range names {
		opt := mod.Options[name]
		if opt == nil || opt.Internal {
			continue
		}
		if strings.EqualFold(opt.Type, "bool") {
			token := "--" + name
			if !opt.Required {
				if b, err := strconv.ParseBool(opt.Val); err == nil && b {
					// The console flag defaults to true; show how to turn it off.
					token = "[--" + name + "=false]"
				} else {
					token = "[" + token + "]"
				}
			}
			parts = append(parts, token)
			continue
		}
		placeholder := "<value>"
		if len(opt.Vals) > 0 {
			placeholder = "<" + strings.Join(opt.Vals, "|") + ">"
		} else if opt.Val != "" {
			placeholder = shellQuote(opt.Val)
		}
		token := "--" + name + " " + placeholder
		if !opt.Required {
			token = "[" + token + "]"
		}
		parts = append(parts, token)
	}
	return strings.Join(parts, " ")
}

func similarModules(name string) string {
	needle := strings.ToLower(strings.TrimSpace(name))
	if needle == "" {
		return ""
	}
	var matches []string
	def.ForEachModule(func(modName string, mod *def.ModuleConfig) {
		if mod == nil {
			return
		}
		if strings.Contains(strings.ToLower(modName), needle) ||
			strings.Contains(strings.ToLower(mod.Comment), needle) {
			matches = append(matches, modName)
		}
	})
	sort.Strings(matches)
	if len(matches) > 10 {
		matches = matches[:10]
	}
	if len(matches) == 0 {
		return ""
	}
	return "; similar modules: " + strings.Join(matches, ", ")
}

func (rt *toolRuntime) listAgents(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Agent string `json:"agent"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("parse arguments: %w", err)
		}
	}
	filter := strings.TrimSpace(args.Agent)
	type processRow struct {
		PID     int    `json:"pid"`
		PPID    int    `json:"ppid"`
		Cmdline string `json:"cmdline,omitempty"`
		Parent  string `json:"parent,omitempty"`
	}
	type row struct {
		Tag            string      `json:"tag"`
		UUID           string      `json:"uuid,omitempty"`
		Name           string      `json:"name,omitempty"`
		Version        string      `json:"version,omitempty"`
		Transport      string      `json:"transport,omitempty"`
		Hostname       string      `json:"hostname,omitempty"`
		Hardware       string      `json:"hardware,omitempty"`
		Container      string      `json:"container,omitempty"`
		Uptime         string      `json:"uptime,omitempty"`
		Groups         string      `json:"groups,omitempty"`
		CPU            string      `json:"cpu,omitempty"`
		GPU            string      `json:"gpu,omitempty"`
		Mem            string      `json:"mem,omitempty"`
		OS             string      `json:"os,omitempty"`
		GOOS           string      `json:"goos,omitempty"`
		Kernel         string      `json:"kernel,omitempty"`
		Arch           string      `json:"arch,omitempty"`
		GOArch         string      `json:"goarch,omitempty"`
		From           string      `json:"from,omitempty"`
		IPs            []string    `json:"ips,omitempty"`
		ARP            []string    `json:"arp,omitempty"`
		User           string      `json:"user,omitempty"`
		Root           bool        `json:"root"`
		Internet       bool        `json:"internet"`
		NCSI           bool        `json:"ncsi"`
		Process        *processRow `json:"process,omitempty"`
		Exes           []string    `json:"exes,omitempty"`
		CWD            string      `json:"cwd,omitempty"`
		Product        string      `json:"product,omitempty"`
		C2Host         string      `json:"c2_host,omitempty"`
		LastSeen       string      `json:"last_seen,omitempty"`
		LastSeenRTTms  float64     `json:"last_seen_rtt_ms,omitempty"`
		MeshRoute      string      `json:"mesh_route,omitempty"`
		P2PRelayPort   string      `json:"p2p_relay_port,omitempty"`
		MeshGossipPort string      `json:"mesh_gossip_port,omitempty"`
		Files          []string    `json:"files,omitempty"`
		P2PTransport   string      `json:"p2p_transport,omitempty"`
		Owner          string      `json:"owner,omitempty"`
		OfflineGrace   int         `json:"offline_grace,omitempty"`
		Impl           string      `json:"implementation,omitempty"`
		Selected       bool        `json:"selected"`
	}
	active := ""
	if rt.target != nil {
		active = rt.target.Tag
	}
	list := agents.GetConnectedAgents()
	rows := make([]row, 0, len(list))
	for _, a := range list {
		if a == nil {
			continue
		}
		if filter != "" && !strings.EqualFold(strings.TrimSpace(a.Tag), filter) {
			continue
		}
		r := row{
			Tag:            sanitize.SanitizeText(a.Tag),
			UUID:           sanitize.SanitizeText(a.UUID),
			Name:           sanitize.SanitizeText(a.Name),
			Version:        sanitize.SanitizeText(a.Version),
			Transport:      sanitize.SanitizeText(a.Transport),
			Hostname:       sanitize.SanitizeText(a.Hostname),
			Hardware:       sanitize.SanitizeText(a.Hardware),
			Container:      sanitize.SanitizeText(a.Container),
			Uptime:         sanitize.SanitizeText(a.Uptime),
			Groups:         sanitize.SanitizeText(a.Groups),
			CPU:            sanitize.SanitizeText(a.CPU),
			GPU:            sanitize.SanitizeText(a.GPU),
			Mem:            sanitize.SanitizeText(a.Mem),
			OS:             sanitize.SanitizeText(a.OS),
			GOOS:           sanitize.SanitizeText(a.GOOS),
			Kernel:         sanitize.SanitizeText(a.Kernel),
			Arch:           sanitize.SanitizeText(a.Arch),
			GOArch:         sanitize.SanitizeText(a.GOArch),
			From:           sanitize.SanitizeText(a.From),
			User:           sanitize.SanitizeText(a.User),
			Root:           a.HasRoot,
			Internet:       a.HasInternet,
			NCSI:           a.NCSIEnabled,
			CWD:            sanitize.SanitizeText(a.CWD),
			Product:        boundedJSON(a.Product, 2048),
			C2Host:         sanitize.SanitizeText(a.C2Host),
			MeshRoute:      sanitize.SanitizeText(a.MeshRoute),
			P2PRelayPort:   sanitize.SanitizeText(a.P2PRelayPort),
			MeshGossipPort: sanitize.SanitizeText(a.MeshGossipPort),
			P2PTransport:   sanitize.SanitizeText(a.P2PTransport),
			Owner:          sanitize.SanitizeText(a.Owner),
			OfflineGrace:   a.OfflineGrace,
			Impl:           sanitize.SanitizeText(a.AgentImpl),
			Selected:       a.Tag == active,
		}
		r.IPs = safeList(a.IPs, 64)
		r.ARP = safeList(a.ARP, 128)
		r.Exes = safeList(a.Exes, 256)
		r.Files = safeList(a.Files, 256)
		if a.Process != nil {
			r.Process = &processRow{
				PID:     a.Process.PID,
				PPID:    a.Process.PPID,
				Cmdline: sanitize.SanitizeText(a.Process.Cmdline),
				Parent:  sanitize.SanitizeText(a.Process.Parent),
			}
		}
		if !a.LastSeen.IsZero() {
			r.LastSeen = a.LastSeen.Format(time.RFC3339)
		}
		if a.LastSeenRTT > 0 {
			r.LastSeenRTTms = float64(a.LastSeenRTT) / float64(time.Millisecond)
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Tag < rows[j].Tag })
	return map[string]any{"agents": rows, "active": active}, nil
}

func safeList(values []string, max int) []string {
	if len(values) == 0 {
		return nil
	}
	if len(values) > max {
		values = values[:max]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, sanitize.SanitizeText(value))
	}
	return out
}

func boundedJSON(value any, max int) string {
	if value == nil {
		return ""
	}
	data, err := json.Marshal(value)
	if err != nil {
		return sanitize.SanitizeText(fmt.Sprint(value))
	}
	text := sanitize.SanitizeOneLine(string(data))
	if len(text) > max {
		text = text[:max]
	}
	return text
}

type listJobsArgs struct {
	Limit int    `json:"limit"`
	Agent string `json:"agent"`
}

func (rt *toolRuntime) listJobs(_ context.Context, raw json.RawMessage) (any, error) {
	var args listJobsArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > maxJobResults {
		limit = maxJobResults
	}
	agentTag := strings.TrimSpace(args.Agent)

	all := jobs.GetJobs()
	sort.Slice(all, func(i, j int) bool { return all[i].Created.After(all[j].Created) })
	type row struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Module    string `json:"module"`
		Agent     string `json:"agent"`
		Status    string `json:"status"`
		Created   string `json:"created"`
		HasOutput bool   `json:"has_output"`
	}
	rows := make([]row, 0, limit)
	for _, job := range all {
		if job == nil {
			continue
		}
		if agentTag != "" && job.AgentTag != agentTag {
			continue
		}
		_, hasOutput := live.CmdResultString(job.ID)
		rows = append(rows, row{
			ID:        job.ID,
			Name:      sanitize.SanitizeText(job.Name),
			Module:    sanitize.SanitizeText(job.Module),
			Agent:     sanitize.SanitizeText(job.AgentTag),
			Status:    jobStatus(job.Status),
			Created:   job.Created.Format(time.RFC3339),
			HasOutput: hasOutput,
		})
		if len(rows) >= limit {
			break
		}
	}
	return map[string]any{"jobs": rows}, nil
}

func jobStatus(status def.JobStatus) string {
	switch status {
	case def.JobStatusPending:
		return "pending"
	case def.JobStatusRunning:
		return "running"
	case def.JobStatusCompleted:
		return "completed"
	case def.JobStatusFailed:
		return "failed"
	default:
		return "unknown"
	}
}

type readJobArgs struct {
	JobID  string `json:"job_id"`
	Offset int64  `json:"offset"`
	Limit  int64  `json:"limit"`
	Tail   bool   `json:"tail"`
}

func (rt *toolRuntime) readJobOutput(_ context.Context, raw json.RawMessage) (any, error) {
	var args readJobArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	jobID, err := canonicalJobID(args.JobID)
	if err != nil {
		return nil, err
	}
	if isBinaryJob(jobID) {
		return nil, fmt.Errorf("job %s returns binary output; use result_summary", jobID)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = defaultReadBytes
	}
	if limit > maxReadBytes {
		limit = maxReadBytes
	}

	if out, ok := live.CmdResultString(jobID); ok {
		return sliceOutput(jobID, "console-cache", sanitize.SanitizeText(out), args.Offset, limit, args.Tail), nil
	}
	resp, err := client.GetJobOutput(jobID, args.Offset, limit, args.Tail)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"job_id":    jobID,
		"source":    "server",
		"size":      resp.Size,
		"truncated": resp.Truncated,
		"output":    sanitize.SanitizeText(resp.Output),
	}, nil
}

type resultSummaryArgs struct {
	JobID string `json:"job_id"`
}

func (rt *toolRuntime) resultSummary(_ context.Context, raw json.RawMessage) (any, error) {
	var args resultSummaryArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	jobID, err := canonicalJobID(args.JobID)
	if err != nil {
		return nil, err
	}
	out, truncated, err := loadJobOutput(jobID, rt.cfg.MaxResultBytes)
	if err != nil {
		return nil, err
	}
	jobName := ""
	if job := jobs.GetJob(jobID); job != nil {
		jobName = job.Name
	}
	return summarizeOutput(jobName, out, truncated), nil
}

// SummarizeJob is the console-facing entry point for `ask --job`.
func SummarizeJob(jobID string, maxBytes int64) (any, error) {
	id, err := canonicalJobID(jobID)
	if err != nil {
		return nil, err
	}
	out, truncated, err := loadJobOutput(id, maxBytes)
	if err != nil {
		return nil, err
	}
	jobName := ""
	if job := jobs.GetJob(id); job != nil {
		jobName = job.Name
	}
	return summarizeOutput(jobName, out, truncated), nil
}

func canonicalJobID(raw string) (string, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("job_id must be a UUID")
	}
	return id.String(), nil
}

func loadJobOutput(jobID string, maxBytes int64) (string, bool, error) {
	if out, ok := live.CmdResultString(jobID); ok {
		if maxBytes > 0 && int64(len(out)) > maxBytes {
			return out[:maxBytes], true, nil
		}
		return out, false, nil
	}
	limit := maxBytes
	if limit <= 0 {
		limit = defaultMaxResultBytes
	}
	resp, err := client.GetJobOutput(jobID, 0, limit, false)
	if err != nil {
		return "", false, err
	}
	return resp.Output, resp.Truncated, nil
}

func sliceOutput(jobID, source, out string, offset, limit int64, tail bool) map[string]any {
	size := int64(len(out))
	if size == 0 {
		return map[string]any{"job_id": jobID, "source": source, "size": 0, "truncated": false, "output": ""}
	}
	if tail {
		offset = size - limit
		if offset < 0 {
			offset = 0
		}
	}
	if offset < 0 {
		offset = 0
	}
	if offset > size {
		offset = size
	}
	end := offset + limit
	if end > size {
		end = size
	}
	return map[string]any{
		"job_id":    jobID,
		"source":    source,
		"size":      size,
		"offset":    offset,
		"truncated": offset > 0 || end < size,
		"output":    out[offset:end],
	}
}

func isBinaryJob(jobID string) bool {
	job := jobs.GetJob(jobID)
	if job == nil {
		return false
	}
	switch commandName(job.Name) {
	case "ps", "ls", "stat", "list_tokens", "list_sessions", "ls_dir":
		return true
	}
	return false
}

func commandName(jobName string) string {
	fields := strings.Fields(strings.TrimSpace(jobName))
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimPrefix(fields[0], "!")
}

func summarizeOutput(jobName, out string, truncated bool) any {
	switch commandName(jobName) {
	case "ps":
		if parsed, err := controllers.ParsePSOutput([]byte(out)); err == nil {
			return tableSummary("process list", parsed, truncated)
		}
	case "ls":
		if parsed, err := controllers.ParseLSOutput([]byte(out)); err == nil {
			return tableSummary("directory listing", parsed, truncated)
		}
	case "stat":
		if parsed, err := controllers.ParseStatOutput([]byte(out)); err == nil {
			return tableSummary("file stat", parsed, truncated)
		}
	case "list_tokens":
		if parsed, err := controllers.ParseTokensOutput([]byte(out)); err == nil {
			return tableSummary("cached tokens", parsed, truncated)
		}
	case "list_sessions":
		if parsed, err := controllers.ParseSessionsOutput([]byte(out)); err == nil {
			return tableSummary("logon sessions", parsed, truncated)
		}
	}
	// Table parsers above consume CBOR, so sanitize only text formats.
	clean := sanitize.SanitizeText(out)
	if looksLikeLDAP(clean) {
		return summarizeLDAP(clean, truncated)
	}
	return genericSummary(clean, truncated)
}

func tableSummary(format string, parsed *controllers.ParsedCommandOutput, truncated bool) any {
	// Parsed cells come from the target (filenames, process names, users) and
	// are not sanitized by the CBOR parsers. The model sees this JSON, so
	// collapse each cell to one bounded line.
	const maxCellBytes = 1024
	total := len(parsed.Rows)
	rows := parsed.Rows
	if len(rows) > maxTableRows {
		rows = rows[:maxTableRows]
	}
	headers := make([]string, 0, len(parsed.Headers))
	for _, h := range parsed.Headers {
		headers = append(headers, sanitizeCell(h, maxCellBytes))
	}
	cleanRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		clean := make([]string, len(row))
		for i, cell := range row {
			clean[i] = sanitizeCell(cell, maxCellBytes)
		}
		cleanRows = append(cleanRows, clean)
	}
	return map[string]any{
		"format":     format,
		"headers":    headers,
		"rows":       cleanRows,
		"total_rows": total,
		"truncated":  truncated || total > len(rows),
	}
}

func sanitizeCell(cell string, limit int) string {
	cell = sanitize.SanitizeOneLine(cell)
	if len(cell) > limit {
		cell = cell[:limit]
	}
	return cell
}

func genericSummary(out string, truncated bool) any {
	const edge = 4096
	if len(out) <= 2*edge {
		return map[string]any{
			"format":    "text",
			"bytes":     len(out),
			"text":      out,
			"truncated": truncated,
		}
	}
	return map[string]any{
		"format":    "text",
		"bytes":     len(out),
		"head":      out[:edge],
		"tail":      out[len(out)-edge:],
		"truncated": true,
	}
}

type reviewArgs struct {
	Module  string         `json:"module"`
	Flags   map[string]any `json:"flags"`
	Command string         `json:"command"`
}

// maxExecCommandBytes bounds one reviewed shell command. The agent shell has no
// need for longer input, and a bound keeps tool results small.
const maxExecCommandBytes = 4096

func (rt *toolRuntime) reviewCommand(_ context.Context, raw json.RawMessage) (any, error) {
	var args reviewArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	name := strings.TrimSpace(args.Module)
	execCmd := strings.TrimSpace(args.Command)
	if name == "" && execCmd == "" {
		return nil, fmt.Errorf("provide either module or command")
	}
	if name != "" && execCmd != "" {
		return nil, fmt.Errorf("provide either module or command, not both")
	}

	if execCmd != "" {
		if len(execCmd) > maxExecCommandBytes {
			return nil, fmt.Errorf("command is longer than %d bytes", maxExecCommandBytes)
		}
		if err := validateSingleLine(execCmd); err != nil {
			return nil, err
		}
		return map[string]any{
			"kind":    "exec",
			"valid":   true,
			"command": "exec --cmd " + shellQuote(execCmd),
			"opsec":   ReviewExec(execCmd, rt.target),
		}, nil
	}

	mod, ok := def.GetModule(name)
	if !ok {
		return nil, fmt.Errorf("module %q not found%s", name, similarModules(name))
	}
	command, problems, supplied := renderModuleCommand(mod, args.Flags)
	result := map[string]any{
		"kind":     "module",
		"module":   mod.Name,
		"valid":    len(problems) == 0,
		"command":  command,
		"usage":    usageLine(mod),
		"examples": mod.Examples,
		"opsec":    ReviewModule(mod, supplied, command, rt.target),
	}
	if len(problems) > 0 {
		result["problems"] = problems
		result["status"] = "invalid"
	}
	return result, nil
}

// RenderModuleCommand validates flags and renders the exact console command.
func RenderModuleCommand(mod *def.ModuleConfig, flags map[string]string) (string, []string) {
	command, problems, _ := NormalizeModuleFlags(mod, flags)
	return command, problems
}

// NormalizeModuleFlags validates flags, applies required defaults, and returns
// the exact console command plus the normalized flag map used for dispatch.
func NormalizeModuleFlags(mod *def.ModuleConfig, flags map[string]string) (string, []string, map[string]string) {
	values := make(map[string]any, len(flags))
	for k, v := range flags {
		values[k] = v
	}
	return renderModuleCommand(mod, values)
}

// ValidateCommandLine rejects control characters in a proposed shell command.
func ValidateCommandLine(s string) error {
	return validateSingleLine(s)
}

// validateSingleLine rejects control characters that could turn one proposed
// command into several or corrupt the console rendering.
func validateSingleLine(s string) error {
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == 0:
			return fmt.Errorf("command must be a single line without control characters")
		case r < 0x20 && r != '\t':
			return fmt.Errorf("command contains a control character")
		case unicode.Is(unicode.Cf, r):
			return fmt.Errorf("command contains a formatting character")
		}
	}
	return nil
}

// renderModuleCommand validates flag values and renders the exact console
// command. It also returns the normalized flag map for a real dispatch.
func renderModuleCommand(mod *def.ModuleConfig, values map[string]any) (string, []string, map[string]string) {
	supplied := make(map[string]string, len(values))
	var problems []string
	for key, value := range values {
		opt, exists := mod.Options[key]
		if !exists || opt == nil {
			problems = append(problems, fmt.Sprintf("unknown option --%s", key))
			continue
		}
		if opt.Internal {
			problems = append(problems, fmt.Sprintf("--%s is filled in by the C2 and has no console flag", key))
			continue
		}
		val := stringifyFlag(value)
		if err := modconfig.ValidateOption(opt, val); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		supplied[key] = val
	}
	for key, opt := range mod.Options {
		if opt == nil || opt.Internal || !opt.Required {
			continue
		}
		val, ok := supplied[key]
		if !ok {
			val = opt.Val
		}
		if strings.TrimSpace(val) == "" {
			problems = append(problems, fmt.Sprintf("required option --%s is missing", key))
		}
	}

	names := make([]string, 0, len(mod.Options))
	for key := range mod.Options {
		names = append(names, key)
	}
	sort.Strings(names)
	parts := []string{mod.Name}
	for _, key := range names {
		opt := mod.Options[key]
		if opt == nil || opt.Internal {
			continue
		}
		val, explicit := supplied[key]
		if !explicit {
			if !opt.Required || strings.TrimSpace(opt.Val) == "" {
				continue
			}
			val = opt.Val
		}
		if strings.EqualFold(opt.Type, "bool") {
			b, _ := strconv.ParseBool(val)
			if b {
				parts = append(parts, "--"+key)
			} else {
				parts = append(parts, "--"+key+"=false")
			}
			continue
		}
		parts = append(parts, "--"+key, shellQuote(val))
	}
	return strings.Join(parts, " "), problems, supplied
}

func stringifyFlag(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if v == math.Trunc(v) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_./:=@%+-,", r):
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
