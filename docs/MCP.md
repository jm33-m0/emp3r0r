# MCP Server Development

This guide covers changing the MCP server. Operator-facing help is served by
the protocol:

- `tools/list` returns every tool with its description and input schema.
- The `initialize` result carries the workflow, OPSEC rules, and result-shape
  guidance.
- `module_help` returns each module's authoritative description, parameters,
  usage line, examples, workspace path, and OPSEC metadata.
- `emp3r0r mcp --help` returns the process flags.

Do not duplicate that content here. When behavior changes, update the tool
description or module manifest in the same change.

## Packages

| Path | Role |
| --- | --- |
| `internal/cc/mcp/server.go` | stdio JSON-RPC framing, `initialize`, `tools/list`, `tools/call`. |
| `internal/cc/mcp/toolset.go` | Merges read-only, action, built-in, and control tools; later sets override earlier names. |
| `internal/cc/mcp/readtools.go` | Read-only C2, job, log, and review tools. |
| `internal/cc/mcp/actions.go` | Target selection, module execution, transfers, reloads, and policy inspection. |
| `internal/cc/mcp/builtin.go` | Typed built-in target operations such as `ls`, `ps`, `cd`, and `rm`. |
| `internal/cc/mcp/control_tools.go` | C2-side controls such as SOCKS5 pivots, TUN routing, and operator resume. |
| `internal/cc/mcp/generate.go` | Go and C agent builders. |
| `internal/cc/mcp/opsec.go` | Deterministic OPSEC capability review. |
| `internal/cc/mcp/audit.go` | Pre- and post-execution audit records. |
| `internal/cc/mcp/executor.go` | Production bridge to the operator client and builders. |

## Adding a tool

1. Put the tool in the builder that owns its lifecycle: read-only in
   `buildReadTools`, target actions in `Actions.Tools`, built-in agent
   operations in `builtinTools`, C2 controls in `controlTools`.
2. Write a self-contained description: purpose, arguments, result fields,
   target requirement, and any OPSEC or reversibility constraint. This is the
   only operator-facing documentation for the tool.
3. Declare the input schema with `ObjectSchema`, `StringProp`,
   `IntegerProp`, and `BooleanProp`. Mark required arguments.
4. Set `ReadOnly` only when the tool cannot change target or C2 state. Set
   `Destructive` when it can.
5. Route execution through `Executor`; never call console handlers, and never
   add a generic command pass-through.
6. Audit every mutating call through the existing `screen` or `runControl`
   path. Read-only tools return data directly.
7. Update `TestMergedToolsetScreensActions` in `server_test.go`: the tool count
   and the expected-name list are checked there.

### Built-in target tools

`builtin.go` maps one tool to one built-in agent command. Use a
`controllers.Build*Command` helper when one exists, validate arguments with
`builtinPath` or `ValidateCommandLine`, and call `runBuiltin`. C agents that do
not run built-in commands are rejected with a directive to use `run_module`.

### C2 control tools

Expose the operation in `internal/cc/operator` first, then add an `Executor`
method and a tool in `control_tools.go`. Use `runControl` so the call is
screened, audited, and rate-limited. Targeted controls receive the active
target; operator-local controls pass `nil`.

## Read-only tooling

Read tools must bound every result:

- `read_job_output` clamps offset, limit, and tail.
- `result_summary` parses known formats and caps table rows.
- `read_log` caps lines and treats the log as hostile data.
- `module_help` sanitizes manifest text before returning it.

Target output is untrusted. Keep it out of instructions, and never evaluate it
as code.

## OPSEC and audit

The review is deterministic capability matching, not intent detection. Tool
handlers build a `def.OpsecReview`, then:

- `screen` or `screenWithFlags` consumes a rate-limit token, evaluates the
  policy, and writes the `decision` audit record before execution.
- `actionResult` writes the `result` audit record and returns `executed`,
  `job_id`, `opsec`, `decision`, and `warnings`.
- `actionBlocked` returns `blocked: true` and never reaches the executor.

Policy evaluation order, capability IDs, and the hardened autonomous policy
belong in `docs/SECURITY.md`; changing a capability rule belongs in
`opsec_rules.go` with a test in `opsec_test.go`.

## Tests

Run the MCP package under the race detector:

```bash
go test -race ./internal/cc/mcp
```

Cover argument validation, blocked actions, and the Executor boundary. Do not
assert exact tool-description prose; test the behavior a client can observe.
