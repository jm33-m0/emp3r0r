package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/assistant"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/operator"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/opsec"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/sanitize"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const maxActionCommandBytes = 4096

// Executor is the narrow C2 surface the action tools need. Production uses the
// operator client; tests use a recorder.
type Executor interface {
	RunModule(ctx context.Context, target *def.Emp3r0rAgent, module string, flags map[string]string) (string, error)
	BuildLocalModule(ctx context.Context, module string, flags map[string]string) (string, error)
	RunExec(ctx context.Context, target *def.Emp3r0rAgent, command string, shell bool) (string, error)
	RunCommand(ctx context.Context, target *def.Emp3r0rAgent, command string) (string, error)
	UploadFile(ctx context.Context, target *def.Emp3r0rAgent, src, dst string) (string, error)
	DownloadFile(ctx context.Context, target *def.Emp3r0rAgent, path, filter string, recursive bool) (string, error)
	ReloadModules(ctx context.Context) error
}

// Actions holds the mutating MCP tools. Every tool screens its action through
// Policy before calling Executor, then records the decision.
type Actions struct {
	Target   func() *def.Emp3r0rAgent
	Select   func(context.Context, string) (*def.Emp3r0rAgent, error)
	Policy   opsec.Policy
	Audit    *Audit
	Limiter  *Limiter
	Executor Executor
	Operator string
	// DefaultCC is the C2 address captured when the MCP session starts. It is
	// the fallback for generate and generate_c when the caller omits cc.
	// Builders mutate live.RuntimeConfig, so reading it per call would make an
	// earlier explicit cc leak into later builds.
	DefaultCC string

	// RunOperator executes one operator console command line. The console
	// command tree owns target selection, filesystem, FTP, pivot, and build
	// commands; Actions screens the line before calling it.
	RunOperator func(context.Context, string) error

	selectMu sync.Mutex

	// generateMu serializes agent builds: the builder mutates the shared
	// runtime config and the on-disk operator config.
	generateMu sync.Mutex
}

// Tools returns the action tools keyed by MCP name.
func (a *Actions) Tools() map[string]assistant.Tool {
	tools := map[string]assistant.Tool{
		"select_agent": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "select_agent",
					Description: "Select one connected agent as the active target. Call list_agents first. The C2's operator lock still applies.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"agent": assistant.StringProp("Agent tag from list_agents"),
					}, "agent"),
				},
			},
			Run: a.selectAgent,
		},
		"run_module": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "run_module",
					Description: "Validate a module invocation, screen its OPSEC review, and execute it. Payload modules run on the target; local C2 modules are built and their build log is returned. The screen may block the action.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"module": assistant.StringProp("Exact module name from list_modules"),
						"flags": map[string]any{
							"type":                 "object",
							"description":          "Flag name to value. Boolean flags take true or false.",
							"additionalProperties": map[string]any{"type": "string"},
						},
					}, "module"),
				},
			},
			Destructive: true,
			Run:         a.runModule,
		},
		"run_exec": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "run_exec",
					Description: "Execute one shell command on the selected target after the OPSEC screen. A C agent uses the exec BOF; a Go agent executes the program directly.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"command": assistant.StringProp("Single-line command"),
						"shell":   assistant.BooleanProp("Run through a shell on a C agent (default true)"),
					}, "command"),
				},
			},
			Destructive: true,
			Run:         a.runExec,
		},
		"run_command": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "run_command",
					Description: "Send a built-in agent command line, such as 'ls --dst /tmp' or 'ps', to the selected target after the OPSEC screen. Use run_module for modules and run_exec for arbitrary shell commands.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"command": assistant.StringProp("Single-line agent command, for example 'ls --dst /tmp'"),
					}, "command"),
				},
			},
			Destructive: true,
			Run:         a.runCommand,
		},
		"command": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "command",
					Description: "Run an operator console command line, such as '/target 1a2b3c4d', '/ls /tmp', or '/jobs'. The leading slash is optional. Target commands are screened by the OPSEC policy; local commands are audited. Module names, exec, put, get, generate, and generate_c are rejected in favor of their dedicated tools. Output goes to the operator log; use read_log and list_jobs.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"command": assistant.StringProp("Operator command line, for example '/target 1a2b3c4d'"),
					}, "command"),
				},
			},
			Destructive: true,
			Run:         a.operatorCommand,
		},
		"upload_file": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "upload_file",
					Description: "Upload one local file to the selected target. The destination defaults to memfs:///<file name>, which keeps the body in encrypted agent memory; pass dst to choose another memfs key or a target disk path. A disk destination carries filesystem-artifact and is warned under the default policy. The returned job ID tracks the target's fetch.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"src": assistant.StringProp("Local file path on the operator host"),
						"dst": assistant.StringProp("Destination on the target: memfs:///name or an absolute disk path. Defaults to memfs:///<file name>"),
					}, "src"),
				},
			},
			Destructive: true,
			Run:         a.uploadFile,
		},
		"download_file": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "download_file",
					Description: "Download a file or directory from the selected target into the operator download directory. A directory is listed; set recursive to download every matching file. Data transfer carries a warning by default.",
					Parameters: assistant.ObjectSchema(map[string]any{
						"path":      assistant.StringProp("Remote file or directory path"),
						"recursive": assistant.BooleanProp("Download every file in a directory listing"),
						"regex":     assistant.StringProp("Regular expression to filter directory listings"),
					}, "path"),
				},
			},
			Run: a.downloadFile,
		},
		"reload_modules": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "reload_modules",
					Description: "Rescan the module directories after editing or adding a module. The module watcher also reloads on file changes.",
					Parameters:  assistant.ObjectSchema(map[string]any{}),
				},
			},
			Run: a.reloadModules,
		},
		"opsec_policy": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "opsec_policy",
					Description: "Return the capability screen: per-capability allow, warn, or block modes, maximum noise, reversibility, module lists, and rate limit.",
					Parameters:  assistant.ObjectSchema(map[string]any{}),
				},
			},
			ReadOnly: true,
			Run:      a.policyInfo,
		},
	}
	for name, tool := range a.generateTools() {
		tools[name] = tool
	}
	return tools
}

type moduleArgs struct {
	Module string         `json:"module"`
	Flags  map[string]any `json:"flags"`
}

func (a *Actions) runModule(ctx context.Context, raw json.RawMessage) (any, error) {
	var args moduleArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	name := strings.TrimSpace(args.Module)
	if name == "" {
		return nil, fmt.Errorf("module is required")
	}
	if len(name) > 256 {
		return nil, fmt.Errorf("module name is too long")
	}
	mod, ok := def.GetModule(name)
	if !ok || mod == nil {
		return nil, fmt.Errorf("module %q is not installed", name)
	}
	flags := map[string]string{}
	for key, value := range args.Flags {
		val := flagString(value)
		if len(key) > 128 || len(val) > 8192 {
			return nil, fmt.Errorf("flag %q or its value is too long", key)
		}
		flags[key] = val
	}
	command, problems, normalized := assistant.NormalizeModuleFlags(mod, flags)
	if len(problems) > 0 {
		return map[string]any{
			"executed": false,
			"valid":    false,
			"module":   mod.Name,
			"command":  command,
			"problems": problems,
		}, nil
	}
	if mod.IsLocal {
		for key, value := range normalized {
			if err := validateLocalBuildPath(key, value); err != nil {
				return nil, fmt.Errorf("flag --%s: %w", key, err)
			}
		}
	}
	target := a.target()
	if !mod.IsLocal && target == nil {
		return map[string]any{
			"executed": false,
			"module":   mod.Name,
			"command":  command,
			"reason":   "no active target; call list_agents and select_agent",
		}, nil
	}
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}
	review := assistant.ReviewModule(mod, normalized, command, target)
	decision, auditErr := a.screenWithFlags("run_module", mod.Name, command, normalized, target, review)
	if !decision.Allowed {
		return actionBlocked("run_module", command, mod.Name, target, review, decision, auditErr), nil
	}

	if mod.IsLocal {
		out, err := a.Executor.BuildLocalModule(ctx, mod.Name, normalized)
		result := a.actionResultWithFlags("run_module", command, mod.Name, normalized, target, review, decision, auditErr, "", err, true)
		result["local"] = true
		result["output"] = truncate(out, 64<<10)
		if err != nil {
			result["error"] = err.Error()
		}
		return result, nil
	}

	jobID, err := a.Executor.RunModule(ctx, target, mod.Name, normalized)
	result := a.actionResultWithFlags("run_module", command, mod.Name, normalized, target, review, decision, auditErr, jobID, err, err == nil)
	if err != nil {
		result["error"] = err.Error()
	}
	return result, nil
}

type execArgs struct {
	Command string `json:"command"`
	Shell   *bool  `json:"shell"`
}

func (a *Actions) runExec(ctx context.Context, raw json.RawMessage) (any, error) {
	var args execArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	command := strings.TrimSpace(args.Command)
	if err := validateActionCommand(command); err != nil {
		return nil, err
	}
	target := a.target()
	if target == nil {
		return map[string]any{"executed": false, "command": command, "reason": "no active target; call list_agents and select_agent"}, nil
	}
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}
	review := assistant.ReviewExec(command, target)
	decision, auditErr := a.screen("run_exec", "", command, target, review)
	if !decision.Allowed {
		return actionBlocked("run_exec", command, "", target, review, decision, auditErr), nil
	}
	shell := true
	if args.Shell != nil {
		shell = *args.Shell
	}
	jobID, err := a.Executor.RunExec(ctx, target, command, shell)
	result := a.actionResult("run_exec", command, "", target, review, decision, auditErr, jobID, err, err == nil)
	if err != nil {
		result["error"] = err.Error()
	}
	return result, nil
}

type commandArgs struct {
	Command string `json:"command"`
}

func (a *Actions) runCommand(ctx context.Context, raw json.RawMessage) (any, error) {
	var args commandArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	command := strings.TrimSpace(args.Command)
	if err := validateActionCommand(command); err != nil {
		return nil, err
	}
	tokens := util.ParseCmd(command)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("command is empty")
	}
	first := strings.TrimLeft(tokens[0], "\"'\\")
	if first == "" {
		return nil, fmt.Errorf("command is empty")
	}
	if isInternalAgentCommand(first) {
		return nil, fmt.Errorf("%s is an internal agent API; use run_module for modules and run_exec for shell commands", first)
	}
	if strings.EqualFold(first, "exec") {
		return nil, fmt.Errorf("use run_exec for shell commands")
	}
	if moduleNameFold(first) != "" {
		return nil, fmt.Errorf("%q is a module; use run_module so its OPSEC metadata is screened", first)
	}
	target := a.target()
	if target == nil {
		return map[string]any{"executed": false, "command": command, "reason": "no active target; call list_agents and select_agent"}, nil
	}
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}
	if modules.CanRunExecBOF(target) {
		return nil, fmt.Errorf("this C agent supports only run_exec (the exec BOF), not arbitrary agent commands")
	}
	review := assistant.ReviewBuiltin(strings.Join(tokens, " "), target)
	decision, auditErr := a.screen("run_command", "", command, target, review)
	if !decision.Allowed {
		return actionBlocked("run_command", command, "", target, review, decision, auditErr), nil
	}
	jobID, err := a.Executor.RunCommand(ctx, target, command)
	result := a.actionResult("run_command", command, "", target, review, decision, auditErr, jobID, err, err == nil)
	if err != nil {
		result["error"] = err.Error()
	}
	return result, nil
}

type uploadArgs struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

func (a *Actions) uploadFile(ctx context.Context, raw json.RawMessage) (any, error) {
	var args uploadArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	src, err := transferPath("src", args.Src)
	if err != nil {
		return nil, err
	}
	if err := validateUploadSource(src); err != nil {
		return nil, err
	}
	dst := strings.TrimSpace(args.Dst)
	if dst == "" {
		base := filepath.Base(filepath.Clean(src))
		if base == "." || base == ".." || base == string(filepath.Separator) || base == "" {
			return nil, fmt.Errorf("cannot derive a memfs name from src %q; pass dst", src)
		}
		dst = "memfs:///" + base
	} else if dst, err = transferPath("dst", dst); err != nil {
		return nil, err
	}

	target := a.target()
	if target == nil {
		return map[string]any{"executed": false, "src": src, "dst": dst, "reason": "no active target; call list_agents and select_agent"}, nil
	}
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}

	command := fmt.Sprintf("put --src %s --dst %s", strconv.Quote(src), strconv.Quote(dst))
	review := uploadReview(command, dst, target)
	decision, auditErr := a.screen("upload_file", "", command, target, review)
	if !decision.Allowed {
		result := actionBlocked("upload_file", command, "", target, review, decision, auditErr)
		result["src"] = src
		result["dst"] = dst
		result["memfs"] = util.IsMemPath(dst)
		return result, nil
	}
	jobID, err := a.Executor.UploadFile(ctx, target, src, dst)
	result := a.actionResult("upload_file", command, "", target, review, decision, auditErr, jobID, err, err == nil)
	result["src"] = src
	result["dst"] = dst
	result["memfs"] = util.IsMemPath(dst)
	if err == nil {
		result["note"] = "The target fetches the hosted file on its next poll; read_job_output confirms completion."
	}
	return result, nil
}

func uploadReview(command, dst string, target *def.Emp3r0rAgent) def.OpsecReview {
	review := assistant.ReviewBuiltin(command, target)
	addOperatorRule(&review, "data-transfer", "moves data from the operator to the target")
	if !util.IsMemPath(dst) {
		addOperatorRule(&review, "filesystem-artifact", "writes the file to the target's disk")
	}
	return review
}

type downloadArgs struct {
	Path      string `json:"path"`
	Regex     string `json:"regex"`
	Recursive bool   `json:"recursive"`
}

func (a *Actions) downloadFile(ctx context.Context, raw json.RawMessage) (any, error) {
	var args downloadArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := transferPath("path", args.Path)
	if err != nil {
		return nil, err
	}
	filter := strings.TrimSpace(args.Regex)
	if len(filter) > maxActionCommandBytes {
		return nil, fmt.Errorf("regex is longer than %d bytes", maxActionCommandBytes)
	}
	if filter != "" {
		if err := assistant.ValidateCommandLine(filter); err != nil {
			return nil, fmt.Errorf("regex: %w", err)
		}
	}

	target := a.target()
	if target == nil {
		return map[string]any{"executed": false, "path": path, "reason": "no active target; call list_agents and select_agent"}, nil
	}
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}

	command := fmt.Sprintf("get --path %s", strconv.Quote(path))
	if filter != "" {
		command += fmt.Sprintf(" --regex %s", strconv.Quote(filter))
	}
	if args.Recursive {
		command += " --recursive"
	}
	review := downloadReview(command, target)
	decision, auditErr := a.screen("download_file", "", command, target, review)
	if !decision.Allowed {
		result := actionBlocked("download_file", command, "", target, review, decision, auditErr)
		result["path"] = path
		return result, nil
	}
	localPath, err := a.Executor.DownloadFile(ctx, target, path, filter, args.Recursive)
	result := a.actionResult("download_file", command, "", target, review, decision, auditErr, "", err, err == nil)
	result["path"] = path
	result["recursive"] = args.Recursive
	if filter != "" {
		result["regex"] = filter
	}
	if localPath != "" {
		result["local_path"] = localPath
	}
	return result, nil
}

func downloadReview(command string, target *def.Emp3r0rAgent) def.OpsecReview {
	review := assistant.ReviewBuiltin(command, target)
	addOperatorRule(&review, "data-transfer", "moves data from the target to the operator")
	return review
}

// transferPath validates one operator-supplied transfer path. Paths are passed
// to the agent inside a quoted command, so control and formatting characters
// are rejected before the command is rendered.
func transferPath(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	if len(value) > maxActionCommandBytes {
		return "", fmt.Errorf("%s is longer than %d bytes", name, maxActionCommandBytes)
	}
	if err := assistant.ValidateCommandLine(value); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}

var (
	operatorLocalCommands = map[string]bool{
		"debug":        true,
		"forget_agent": true,
		"help":         true,
		"jobs":         true,
		"ls_modules":   true,
		"ls_targets":   true,
		"resume":       true,
		"search":       true,
		"socks_status": true,
		"socks_stop":   true,
		"target":       true,
		"tun2socks":    true,
	}
	operatorTargetCommands = map[string]bool{
		"cat":         true,
		"cd":          true,
		"cp":          true,
		"decrypt":     true,
		"kill":        true,
		"ls":          true,
		"mkdir":       true,
		"mv":          true,
		"net_helper":  true,
		"ps":          true,
		"pwd":         true,
		"rm":          true,
		"socks_start": true,
		"suicide":     true,
	}
)

// operatorCommand runs a console command line, so an external agent can use
// the operator surface directly, for example as "/target <tag>" or "/ls /tmp".
// It screens target-touching commands before the console handler dispatches
// them and audits both local and target commands.
func (a *Actions) operatorCommand(ctx context.Context, raw json.RawMessage) (any, error) {
	var args commandArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	command := strings.TrimSpace(args.Command)
	command = strings.TrimSpace(strings.TrimPrefix(command, "/"))
	if err := validateActionCommand(command); err != nil {
		return nil, err
	}
	if strings.ContainsAny(command, "\r\n") {
		return nil, fmt.Errorf("command must be a single line")
	}
	fields, err := operator.SplitCommandLine(command)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("command is empty")
	}
	first := strings.ToLower(fields[0])
	if isInternalAgentCommand(first) {
		return nil, fmt.Errorf("%s is an internal agent API; use run_module or run_exec", first)
	}
	switch first {
	case "exit", "quit", "q", "bye", "logout", "shutdown", "stop":
		return nil, fmt.Errorf("%s would terminate the MCP server", first)
	case "reset_layout":
		return nil, fmt.Errorf("reset_layout controls the interactive console and is unavailable over MCP")
	case "ask":
		return nil, fmt.Errorf("ask is an interactive console command and is unavailable over MCP")
	case "exec":
		return nil, fmt.Errorf("use run_exec for shell commands")
	case "put":
		return nil, fmt.Errorf("use upload_file for local file uploads; it applies the protected-file check")
	case "get":
		return nil, fmt.Errorf("use download_file for target downloads")
	case "generate", "generate_c":
		return nil, fmt.Errorf("%s builds an agent on this host; use the %s tool so builds are serialized", first, first)
	}
	if a.RunOperator == nil {
		return nil, fmt.Errorf("operator command runner is not configured")
	}

	if moduleName := moduleNameFold(first); moduleName != "" {
		return nil, fmt.Errorf("%q is a module; use run_module so defaults and flags are normalized and screened", moduleName)
	}
	local := operatorLocalCommands[first]
	target := a.target()
	if !local && target == nil {
		return map[string]any{
			"executed": false,
			"command":  command,
			"reason":   "no active target; call list_agents and select_agent, or use /target",
		}, nil
	}
	if !local && !operatorTargetCommands[first] {
		return nil, fmt.Errorf("unknown operator command %q", first)
	}
	if !local && first != "socks_start" && modules.CanRunExecBOF(target) {
		return nil, fmt.Errorf("this C agent supports only run_exec (the exec BOF), not built-in agent commands")
	}

	var review def.OpsecReview
	if local {
		review = def.OpsecReview{
			Noise:      "low",
			Reversible: true,
			Reasons:    []string{"local operator command; no target execution"},
			Artifacts:  []string{"operator audit entry"},
		}
		if first == "tun2socks" && len(fields) > 1 && strings.EqualFold(fields[1], "start") {
			addOperatorRule(&review, "data-transfer", "routes operator traffic through a SOCKS5 pivot")
		}
		if first == "forget_agent" {
			review.Reversible = false
			addOperatorRule(&review, "destructive", "permanently removes the agent record from the C2")
		}
	} else {
		review = operatorCommandReview(first, command, target)
	}
	decision, auditErr := a.screen("command", "", command, target, review)
	if !decision.Allowed {
		return actionBlocked("command", command, "", target, review, decision, auditErr), nil
	}

	err = a.RunOperator(ctx, command)
	result := map[string]any{
		"executed": err == nil,
		"command":  command,
		"opsec":    review,
		"decision": decision,
		"note":     "The command ran in the operator console. Use read_log for its output and list_jobs for asynchronous work.",
	}
	if len(decision.Warnings) > 0 {
		result["warnings"] = decision.Warnings
	}
	if err != nil {
		result["error"] = err.Error()
	}
	auditErr = a.Audit.Log(AuditRecord{
		Operator: a.Operator, Tool: "command", Target: targetTag(target),
		Command: command, Rules: review.Rules, Noise: review.Noise,
		Allowed: true, Reason: decision.Reason, Error: errorString(err),
	})
	if auditErr != nil {
		result["audit_error"] = auditErr.Error()
	}
	return result, nil
}

// operatorCommandReview scores a console command that touches the target.
// ReviewBuiltin covers the command tree's own file, query, and destructive
// patterns; the explicit rules cover command names whose footprint is not in
// the command text (a pivot or a kill).
func operatorCommandReview(first, command string, target *def.Emp3r0rAgent) def.OpsecReview {
	var review def.OpsecReview
	switch first {
	case "kill", "suicide":
		review = assistant.ReviewExec(command, target)
	default:
		review = assistant.ReviewBuiltin(command, target)
	}
	switch first {
	case "socks_start":
		addOperatorRule(&review, "data-transfer", "moves data between the operator and the target")
	}
	switch first {
	case "cp", "decrypt", "mkdir", "mv":
		addOperatorRule(&review, "filesystem-artifact", "writes files on the target")
	}
	if first == "rm" || first == "suicide" {
		addOperatorRule(&review, "destructive", "removes target state")
	}
	return review
}

func isInternalAgentCommand(token string) bool {
	token = strings.TrimLeft(strings.TrimSpace(token), `"'\`)
	return strings.HasPrefix(token, "!")
}

func addOperatorRule(review *def.OpsecReview, rule, reason string) {
	for _, existing := range review.Rules {
		if strings.EqualFold(existing, rule) {
			return
		}
	}
	review.Rules = append(review.Rules, rule)
	review.Reasons = append(review.Reasons, reason)
}

func (a *Actions) selectAgent(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Agent string `json:"agent"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	tag := strings.TrimSpace(args.Agent)
	if tag == "" {
		return nil, fmt.Errorf("agent is required")
	}
	if len(tag) > 256 {
		return nil, fmt.Errorf("agent tag is too long")
	}
	if a.Select == nil {
		return nil, fmt.Errorf("target selection is not configured")
	}
	a.selectMu.Lock()
	defer a.selectMu.Unlock()
	if ok, wait := a.Limiter.Allow(); !ok {
		return nil, fmt.Errorf("rate limit reached; retry after %s", wait.Round(1000000))
	}
	if err := a.Audit.Log(AuditRecord{
		Operator: a.Operator, Tool: "select_agent", Target: tag,
		Allowed: true, Reason: "target selection requested", Phase: "decision",
	}); err != nil {
		return nil, fmt.Errorf("audit log unavailable; target not selected: %w", err)
	}
	agent, err := a.Select(ctx, tag)
	if err != nil {
		_ = a.Audit.Log(AuditRecord{Operator: a.Operator, Tool: "select_agent", Target: tag, Allowed: false, Error: err.Error(), Phase: "result"})
		return nil, err
	}
	if agent == nil {
		return nil, fmt.Errorf("select_agent: no agent returned")
	}
	_ = a.Audit.Log(AuditRecord{Operator: a.Operator, Tool: "select_agent", Target: tag, Allowed: true, Reason: "target selected", Phase: "result"})
	return map[string]any{
		"selected": sanitize.SanitizeText(agent.Tag),
		"hostname": sanitize.SanitizeText(agent.Hostname),
		"os":       sanitize.SanitizeText(agent.GOOS),
		"user":     sanitize.SanitizeText(agent.User),
	}, nil
}

func (a *Actions) reloadModules(ctx context.Context, _ json.RawMessage) (any, error) {
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}
	review := def.OpsecReview{
		Noise: "low", Reversible: true,
		Reasons: []string{"local module registry reload"},
	}
	decision, auditErr := a.screen("reload_modules", "", "", nil, review)
	if !decision.Allowed {
		return actionBlocked("reload_modules", "", "", nil, review, decision, auditErr), nil
	}
	err := a.Executor.ReloadModules(ctx)
	result := map[string]any{
		"executed": err == nil,
		"opsec":    review,
		"decision": decision,
		"modules":  def.CountModules(),
	}
	if err != nil {
		result["error"] = err.Error()
	}
	_ = a.Audit.Log(AuditRecord{
		Operator: a.Operator, Tool: "reload_modules", Allowed: true, Phase: "result",
		Rules: review.Rules, Noise: review.Noise, Reason: decision.Reason, Error: errorString(err),
	})
	if auditErr != nil {
		result["audit_error"] = auditErr.Error()
	}
	return result, nil
}

func (a *Actions) policyInfo(_ context.Context, _ json.RawMessage) (any, error) {
	p := a.Policy
	out := map[string]any{
		"max_noise":              p.MaxNoise,
		"allow_irreversible":     p.AllowIrreversible,
		"max_actions_per_minute": p.MaxActionsPerMinute,
		"allowed_modules":        p.AllowedModules,
		"denied_modules":         p.DeniedModules,
		"capabilities":           p.Capabilities,
	}
	if err := a.Audit.Log(AuditRecord{
		Operator: a.Operator, Tool: "opsec_policy", Phase: "result",
		Allowed: true, Reason: "policy read",
	}); err != nil {
		return nil, fmt.Errorf("audit log unavailable; result withheld: %w", err)
	}
	return out, nil
}

func (a *Actions) screen(tool, module, command string, target *def.Emp3r0rAgent, review def.OpsecReview) (opsec.Decision, error) {
	return a.screenWithFlags(tool, module, command, nil, target, review)
}

func (a *Actions) screenWithFlags(tool, module, command string, flags map[string]string, target *def.Emp3r0rAgent, review def.OpsecReview) (opsec.Decision, error) {
	if ok, wait := a.Limiter.Allow(); !ok {
		decision := opsec.Decision{
			Reason: fmt.Sprintf("rate limit reached; retry after %s", wait.Round(1000000)),
		}
		err := a.Audit.Log(AuditRecord{
			Operator: a.Operator, Tool: tool, Target: targetTag(target), Module: module,
			Command: command, Flags: flags, Rules: review.Rules, Noise: review.Noise,
			Allowed: false, Reason: decision.Reason, Phase: "decision",
		})
		return decision, err
	}
	decision := a.Policy.Evaluate(module, review)
	rec := AuditRecord{
		Operator: a.Operator, Tool: tool, Target: targetTag(target), Module: module,
		Command: command, Flags: flags, Rules: review.Rules, Noise: review.Noise,
		Allowed: decision.Allowed, Reason: decision.Reason, Phase: "decision",
	}
	if err := a.Audit.Log(rec); err != nil {
		return opsec.Decision{Allowed: false, Reason: "audit log unavailable; action refused"}, err
	}
	return decision, nil
}

func (a *Actions) actionResult(tool, command, module string, target *def.Emp3r0rAgent, review def.OpsecReview, decision opsec.Decision, auditErr error, jobID string, err error, executed bool) map[string]any {
	return a.actionResultWithFlags(tool, command, module, nil, target, review, decision, auditErr, jobID, err, executed)
}

func (a *Actions) actionResultWithFlags(tool, command, module string, flags map[string]string, target *def.Emp3r0rAgent, review def.OpsecReview, decision opsec.Decision, auditErr error, jobID string, err error, executed bool) map[string]any {
	result := map[string]any{
		"executed": executed,
		"opsec":    review,
		"decision": decision,
	}
	if len(decision.Warnings) > 0 {
		result["warnings"] = decision.Warnings
	}
	if jobID != "" {
		result["job_id"] = jobID
	}
	if command != "" {
		result["command"] = command
	}
	if module != "" {
		result["module"] = module
	}
	if module != "" {
		if mod, ok := def.GetModule(module); ok && mod != nil {
			result["module_path"] = mod.Path
		}
	}
	if err != nil {
		result["error"] = err.Error()
	}
	if auditErr != nil {
		result["audit_error"] = auditErr.Error()
		logging.Errorf("mcp audit: %v", auditErr)
	}
	rec := AuditRecord{
		Operator: a.Operator, Tool: tool, Target: targetTag(target), Module: module,
		Command: command, Flags: flags, Rules: review.Rules, Noise: review.Noise,
		Phase: "result", Allowed: decision.Allowed, Reason: decision.Reason,
		JobID: jobID, Error: errorString(err),
	}
	if err := a.Audit.Log(rec); err != nil {
		result["audit_error"] = err.Error()
		logging.Errorf("mcp audit: %v", err)
	}
	return result
}

func actionBlocked(tool, command, module string, target *def.Emp3r0rAgent, review def.OpsecReview, decision opsec.Decision, auditErr error) map[string]any {
	result := map[string]any{
		"executed": false,
		"blocked":  true,
		"opsec":    review,
		"decision": decision,
	}
	if command != "" {
		result["command"] = command
	}
	if module != "" {
		result["module"] = module
	}
	if target != nil {
		result["target"] = targetTag(target)
	}
	if decision.Reason != "" {
		result["reason"] = decision.Reason
	}
	if len(decision.Warnings) > 0 {
		result["warnings"] = decision.Warnings
	}
	if auditErr != nil {
		result["audit_error"] = auditErr.Error()
		logging.Errorf("mcp audit: %v", auditErr)
	}
	return result
}

func moduleNameFold(name string) string {
	found := ""
	def.ForEachModule(func(module string, _ *def.ModuleConfig) {
		if found == "" && strings.EqualFold(module, name) {
			found = module
		}
	})
	return found
}

func (a *Actions) target() *def.Emp3r0rAgent {
	if a.Target == nil {
		return nil
	}
	return a.Target()
}

func targetTag(agent *def.Emp3r0rAgent) string {
	if agent == nil {
		return ""
	}
	return sanitize.SanitizeText(agent.Tag)
}

// validateLocalBuildPath rejects a local module flag that points at a
// protected operator path. Local builds run on the operator/C2 host and can
// write their output path, so an injected model must not be able to overwrite
// policy, audit, or key files through a module flag. File-path flags must also
// resolve to a regular file when they exist: a FIFO would block the build.
func validateLocalBuildPath(flag, value string) error {
	if value == "" {
		return nil
	}
	if forbiddenPath(value) || pseudoFilePath(value) {
		return fmt.Errorf("%q is a protected operator path", value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return nil
	}
	if forbiddenPath(abs) || pseudoFilePath(abs) {
		return fmt.Errorf("%q is a protected operator path", value)
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%q is a symlink", value)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect %q: %w", value, err)
	}
	real, err := evalExisting(abs)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", value, err)
	}
	if forbiddenPath(real) || pseudoFilePath(real) {
		return fmt.Errorf("%q resolves to a protected operator path", value)
	}
	if !isLocalFilePathFlag(flag) {
		return nil
	}
	info, err := os.Lstat(real)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect %q: %w", value, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", value)
	}
	return nil
}

// isLocalFilePathFlag reports whether a module option is expected to be a
// local file path. This keeps remote path options such as stager_linux's
// payload-path out of the regular-file check.
func isLocalFilePathFlag(flag string) bool {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "src", "dst", "output", "out", "outfile", "output-path", "input", "file", "shellcode", "agent-pic", "dll":
		return true
	default:
		return false
	}
}

func validateUploadSource(src string) error {
	if forbiddenPath(src) || forbiddenPath(filepath.Clean(src)) || pseudoFilePath(src) {
		return fmt.Errorf("src %q is a protected operator file", src)
	}
	if abs, err := filepath.Abs(src); err == nil {
		if forbiddenPath(abs) || pseudoFilePath(abs) {
			return fmt.Errorf("src %q is a protected operator file", src)
		}
		if info, err := os.Lstat(abs); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("src %q is a symlink", src)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("src %q is not a regular file", src)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect src %q: %w", src, err)
		}
		real, err := evalExisting(abs)
		if err != nil {
			return fmt.Errorf("resolve src %q: %w", src, err)
		}
		if forbiddenPath(real) || pseudoFilePath(real) {
			return fmt.Errorf("src %q resolves to a protected operator file", src)
		}
	}
	return nil
}

// pseudoFilePath reports whether path is on a virtual filesystem that exposes
// process memory, command lines, or environment. These are not regular
// operator files: /proc/self/cmdline can carry the WireGuard key passed in
// argv and /proc/self/environ can carry provider keys.
func pseudoFilePath(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range []string{"/proc", "/sys", "/dev", "/run"} {
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateActionCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command is empty")
	}
	if len(command) > maxActionCommandBytes {
		return fmt.Errorf("command is longer than %d bytes", maxActionCommandBytes)
	}
	return assistant.ValidateCommandLine(command)
}

func flagString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\n[truncated]"
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
