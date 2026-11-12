package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// builtinTools returns the typed target tools. They replace the former generic
// command pass-through: each tool maps to one built-in agent command, so the
// model chooses an operation instead of composing an agent command line.
func (a *Actions) builtinTools() map[string]Tool {
	return map[string]Tool{
		"ls": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "ls",
					Description: "List a target directory. The path defaults to the agent's current directory. Returns a job ID; read its output with read_job_output or result_summary.",
					Parameters: ObjectSchema(map[string]any{
						"path": StringProp("Target directory; defaults to the agent's current directory"),
					}),
				},
			},
			ReadOnly: true,
			Run:      a.ls,
		},
		"pwd": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "pwd",
					Description: "Print the target agent's current working directory. Returns a job ID; read its output with read_job_output.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			ReadOnly: true,
			Run:      a.pwd,
		},
		"cd": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "cd",
					Description: "Change the target agent's current working directory. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"path": StringProp("Target directory"),
					}, "path"),
				},
			},
			Run: a.cd,
		},
		"cat": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "cat",
					Description: "Read one file on the target. Returns a job ID; read its output with read_job_output or result_summary.",
					Parameters: ObjectSchema(map[string]any{
						"path": StringProp("Target file path"),
					}, "path"),
				},
			},
			ReadOnly: true,
			Run:      a.cat,
		},
		"ps": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "ps",
					Description: "List processes on the target, optionally filtered by PID, user, name, or command line. Returns a job ID; read its output with result_summary.",
					Parameters: ObjectSchema(map[string]any{
						"pid":     IntegerProp("Process ID filter"),
						"user":    StringProp("User name filter"),
						"name":    StringProp("Command name filter, without arguments"),
						"cmdline": StringProp("Command line filter"),
					}),
				},
			},
			ReadOnly: true,
			Run:      a.ps,
		},
		"net_helper": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "net_helper",
					Description: "Return the target's IP addresses, routes, and neighbour table. Returns a job ID; read its output with read_job_output or result_summary.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			ReadOnly: true,
			Run:      a.netHelper,
		},
		"cp": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "cp",
					Description: "Copy one file on the target. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"src": StringProp("Source target path"),
						"dst": StringProp("Destination target path"),
					}, "src", "dst"),
				},
			},
			Destructive: true,
			Run:         a.cp,
		},
		"mv": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "mv",
					Description: "Move or rename one file on the target. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"src": StringProp("Source target path"),
						"dst": StringProp("Destination target path"),
					}, "src", "dst"),
				},
			},
			Destructive: true,
			Run:         a.mv,
		},
		"rm": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "rm",
					Description: "Delete a file or directory on the target. The OPSEC screen treats this as destructive. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"path": StringProp("Target path to delete"),
					}, "path"),
				},
			},
			Destructive: true,
			Run:         a.rm,
		},
		"mkdir": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "mkdir",
					Description: "Create one directory on the target. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"path": StringProp("Target directory to create"),
					}, "path"),
				},
			},
			Destructive: true,
			Run:         a.mkdir,
		},
		"kill": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "kill",
					Description: "Terminate one or more processes on the target by PID. The OPSEC screen treats this as destructive. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"pids": map[string]any{
							"type":        "array",
							"description": "Positive process IDs",
							"items":       map[string]any{"type": "integer"},
							"minItems":    1,
						},
					}, "pids"),
				},
			},
			Destructive: true,
			Run:         a.kill,
		},
		"suicide": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "suicide",
					Description: "Terminate the target agent process and delete its agent root directory. The OPSEC screen treats this as destructive and irreversible. Returns a job ID; the agent must still be online to receive it.",
					Parameters:  ObjectSchema(map[string]any{}),
				},
			},
			Destructive: true,
			Run:         a.suicide,
		},
		"decrypt": {
			Def: ToolDef{
				Type: "function",
				Function: FunctionDef{
					Name:        "decrypt",
					Description: "Decrypt one agent-staged file and write the plaintext on the target. The OPSEC screen treats the write as a filesystem artifact. Returns a job ID; read its output with read_job_output.",
					Parameters: ObjectSchema(map[string]any{
						"path": StringProp("Target path to decrypt"),
						"out":  StringProp("Output path; defaults to <path>.dec"),
					}, "path"),
				},
			},
			Destructive: true,
			Run:         a.decrypt,
		},
	}
}

func (a *Actions) builtinTarget() (*def.Emp3r0rAgent, error) {
	target := a.target()
	if target == nil {
		return nil, fmt.Errorf("no active target; call list_agents and select_agent")
	}
	if modules.CanRunExecBOF(target) {
		return nil, fmt.Errorf("a C agent does not run built-in commands; use run_module")
	}
	if a.Executor == nil {
		return nil, fmt.Errorf("executor is not configured")
	}
	return target, nil
}

func (a *Actions) runBuiltin(ctx context.Context, tool, command string, target *def.Emp3r0rAgent, review def.OpsecReview) (any, error) {
	decision, auditErr := a.screen(tool, "", command, target, review)
	if !decision.Allowed {
		return actionBlocked(tool, command, "", target, review, decision, auditErr), nil
	}
	jobID, err := a.Executor.RunBuiltin(ctx, target, command)
	result := a.actionResult(tool, command, "", target, review, decision, auditErr, jobID, err, err == nil)
	if err == nil {
		result["note"] = "The target runs the command on its next poll; read the job output with read_job_output."
	}
	return result, nil
}

func builtinPath(name, value string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return "", fmt.Errorf("%s is required", name)
		}
		return "", nil
	}
	if len(value) > maxActionCommandBytes {
		return "", fmt.Errorf("%s is longer than %d bytes", name, maxActionCommandBytes)
	}
	if err := ValidateCommandLine(value); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}

func (a *Actions) ls(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPath("path", args.Path, false)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = "."
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildLsCommand(path)
	return a.runBuiltin(ctx, "ls", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) pwd(ctx context.Context, _ json.RawMessage) (any, error) {
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildPwdCommand()
	return a.runBuiltin(ctx, "pwd", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) cd(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPath("path", args.Path, true)
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildCdCommand(path)
	return a.runBuiltin(ctx, "cd", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) cat(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPath("path", args.Path, true)
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildCatCommand(path)
	return a.runBuiltin(ctx, "cat", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) ps(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		PID     int    `json:"pid"`
		User    string `json:"user"`
		Name    string `json:"name"`
		Cmdline string `json:"cmdline"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if args.PID < 0 {
		return nil, fmt.Errorf("pid must be positive")
	}
	for name, value := range map[string]string{"user": args.User, "name": args.Name, "cmdline": args.Cmdline} {
		if _, err := builtinPath(name, value, false); err != nil {
			return nil, err
		}
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildPsCommand(args.PID, strings.TrimSpace(args.User), strings.TrimSpace(args.Name), strings.TrimSpace(args.Cmdline))
	return a.runBuiltin(ctx, "ps", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) netHelper(ctx context.Context, _ json.RawMessage) (any, error) {
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildNetHelperCommand()
	return a.runBuiltin(ctx, "net_helper", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) cp(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPaths(map[string]string{"src": args.Src, "dst": args.Dst})
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildCpCommand(path["src"], path["dst"])
	return a.runBuiltin(ctx, "cp", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) mv(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPaths(map[string]string{"src": args.Src, "dst": args.Dst})
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildMvCommand(path["src"], path["dst"])
	return a.runBuiltin(ctx, "mv", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) rm(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPath("path", args.Path, true)
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildRmCommand(path)
	review := ReviewBuiltin(command, target)
	addOperatorRule(&review, "destructive", "deletes target state")
	return a.runBuiltin(ctx, "rm", command, target, review)
}

func (a *Actions) mkdir(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPath("path", args.Path, true)
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildMkdirCommand(path)
	return a.runBuiltin(ctx, "mkdir", command, target, ReviewBuiltin(command, target))
}

func (a *Actions) kill(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		PIDs []int `json:"pids"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	if len(args.PIDs) == 0 {
		return nil, fmt.Errorf("pids is required")
	}
	if len(args.PIDs) > 256 {
		return nil, fmt.Errorf("at most 256 PIDs are accepted")
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command, err := controllers.BuildKillCommand(args.PIDs)
	if err != nil {
		return nil, err
	}
	review := ReviewBuiltin(command, target)
	addOperatorRule(&review, "destructive", "terminates target processes")
	return a.runBuiltin(ctx, "kill", command, target, review)
}

func (a *Actions) decrypt(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
		Out  string `json:"out"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("parse arguments: %w", err)
	}
	path, err := builtinPath("path", args.Path, true)
	if err != nil {
		return nil, err
	}
	out, err := builtinPath("out", args.Out, false)
	if err != nil {
		return nil, err
	}
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("decrypt --path %s", strconv.Quote(path))
	if out != "" {
		command += fmt.Sprintf(" --out %s", strconv.Quote(out))
	}
	review := ReviewBuiltin(command, target)
	addOperatorRule(&review, "filesystem-artifact", "writes the decrypted plaintext to the target's disk")
	return a.runBuiltin(ctx, "decrypt", command, target, review)
}

func (a *Actions) suicide(ctx context.Context, _ json.RawMessage) (any, error) {
	target, err := a.builtinTarget()
	if err != nil {
		return nil, err
	}
	command := controllers.BuildSuicideCommand()
	review := ReviewBuiltin(command, target)
	review.Reversible = false
	addOperatorRule(&review, "destructive", "terminates the agent and removes its state")
	return a.runBuiltin(ctx, "suicide", command, target, review)
}

func builtinPaths(values map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(values))
	for name, value := range values {
		path, err := builtinPath(name, value, true)
		if err != nil {
			return nil, err
		}
		out[name] = path
	}
	return out, nil
}
