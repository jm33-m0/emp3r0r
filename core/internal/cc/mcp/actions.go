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

	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
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
	UploadFile(ctx context.Context, target *def.Emp3r0rAgent, src, dst string) (string, error)
	DownloadFile(ctx context.Context, target *def.Emp3r0rAgent, path, filter string, recursive bool) (string, error)
	RunBuiltin(ctx context.Context, target *def.Emp3r0rAgent, command string) (string, error)
	ReloadModules(ctx context.Context) error
	ResumeOperator(ctx context.Context) error
	ForgetAgent(ctx context.Context, agent string) (string, error)
	StartSocks5(ctx context.Context, port int, bind string) (operator.Socks5Pivot, error)
	StopSocks5(ctx context.Context, port int) error
	ListSocks5(ctx context.Context) ([]operator.Socks5Pivot, error)
	StartTun2Socks(ctx context.Context, opts operator.Tun2SocksOptions) (operator.Tun2SocksState, error)
	StopTun2Socks(ctx context.Context, name string) error
	Tun2SocksStatus(ctx context.Context) []operator.Tun2SocksState
	SetDebugLevel(ctx context.Context, level int) error
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
	// Detection plans and runs payload detonation tests against a sandbox.
	// It is optional; when nil the detection tools report that it is off.
	Detection *detection.Loop
	// DefaultCC is the C2 address captured when the MCP session starts. It is
	// the fallback for generate and generate_c when the caller omits cc.
	// Builders mutate live.RuntimeConfig, so reading it per call would make an
	// earlier explicit cc leak into later builds.
	DefaultCC string

	selectMu sync.Mutex

	// generateMu serializes agent builds: the builder mutates the shared
	// runtime config and the on-disk operator config.
	generateMu sync.Mutex
}

// Tools returns the action tools keyed by MCP name.
func (a *Actions) Tools() map[string]Tool {
	tools := map[string]Tool{
		"select_agent": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "select_agent",
					Description: "Select one connected agent from list_agents as the active target and acquire the C2 single-owner lock. Takes the agent tag. Another operator holding the lock yields 409.",
					Parameters: ObjectSchema(map[string]any{
						"agent": StringProp("Agent tag from list_agents"),
					}, "agent"),
				},
			},
			Run: a.selectAgent,
		},
		"run_module": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "run_module",
					Description: "Validate, screen, and execute one installed module by exact name. flags maps flag names to string values; booleans are true or false. Payload modules return a job ID; local C2 modules build on the operator host and return their build log. Use module_help first. A blocked result did not execute.",
					Parameters: ObjectSchema(map[string]any{
						"module": StringProp("Exact module name from list_modules"),
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
		"upload_file": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "upload_file",
					Description: "Upload one local file to the selected target. dst defaults to memfs:///<file name>, keeping the body in encrypted agent memory; a disk destination adds filesystem-artifact. Protected operator files are rejected. Returns a job ID that tracks the target fetch.",
					Parameters: ObjectSchema(map[string]any{
						"src": StringProp("Local file path on the operator host"),
						"dst": StringProp("Destination on the target: memfs:///name or an absolute disk path. Defaults to memfs:///<file name>"),
					}, "src"),
				},
			},
			Destructive: true,
			Run:         a.uploadFile,
		},
		"download_file": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "download_file",
					Description: "Download a file or directory from the selected target into the operator download directory. Set recursive to fetch every matching file and regex to filter listings. Returns local_path and the OPSEC decision.",
					Parameters: ObjectSchema(map[string]any{
						"path":      StringProp("Remote file or directory path"),
						"recursive": BooleanProp("Download every file in a directory listing"),
						"regex":     StringProp("Regular expression to filter directory listings"),
					}, "path"),
				},
			},
			Run: a.downloadFile,
		},
		"reload_modules": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "reload_modules",
					Description: "Rescan module directories after adding or editing a module. The module watcher may also reload automatically. Takes no arguments and returns the loaded module count.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			Run: a.reloadModules,
		},
		"opsec_policy": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "opsec_policy",
					Description: "Return the active OPSEC policy: per-capability allow, warn, or block modes, maximum noise, reversibility, module allow and deny lists, and the rate limit. Takes no arguments.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			ReadOnly: true,
			Run:      a.policyInfo,
		},
	}
	for name, tool := range a.generateTools() {
		tools[name] = tool
	}
	for name, tool := range a.builtinTools() {
		tools[name] = tool
	}
	for name, tool := range a.controlTools() {
		tools[name] = tool
	}
	for name, tool := range a.detectionTools() {
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
	command, problems, normalized := NormalizeModuleFlags(mod, flags)
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
	review := ReviewModule(mod, normalized, command, target)
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
		} else if block := a.attachDetection(ctx, mod, out); block != nil {
			result["detection"] = block
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
	review := ReviewBuiltin(command, target)
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
		if err := ValidateCommandLine(filter); err != nil {
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
	review := ReviewBuiltin(command, target)
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
	if err := ValidateCommandLine(value); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
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
	clean := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(path, filepath.VolumeName(path))))
	for _, root := range []string{"/proc", "/sys", "/dev", "/run"} {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
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
