# MCP Server

`emp3r0r mcp` serves the operator surface over the Model Context Protocol on
stdin/stdout. An external agent that speaks MCP — Claude Code, Codex, or any
other MCP client — can select a target, inspect modules, execute commands,
upload and download files, read job output, reload modules, and generate new
agents.

Every mutating call is screened by a deterministic OPSEC engine before reaching
the target. A blocked call returns `executed: false` and does not execute. The
C2 still derives operator identity from the WireGuard peer, audits every
action, and enforces job ownership and single-owner target locks.

## Requirements

- A running C2 server and the operator kit the server prints.
- Loopback for a local C2, or WireGuard for a remote one.
- An MCP client that supports stdio servers and tool calling.
- For `generate`, the agent stubs in the operator workspace. For `generate_c`,
  the installed C agent source, `make`, and the pinned `zig` toolchain.

## Start

Local C2:

```bash
emp3r0r mcp
```

Remote C2:

```bash
emp3r0r mcp \
  --c2-host 203.0.113.10 \
  --server-wg-key "$SERVER_WG_KEY" \
  --server-wg-ip 10.10.10.1 \
  --operator-wg-ip 10.10.10.2 \
  --operator-wg-key-file ~/.emp3r0r/operator.key
```

| Flag | Meaning |
| --- | --- |
| `--c2-host` | C2 server address. Default `127.0.0.1`. |
| `--operator-port` | C2 operator port. Default `13377`. |
| `--server-wg-key` | C2 WireGuard public key. |
| `--server-wg-ip` | C2 WireGuard address. |
| `--operator-wg-ip` | This operator's WireGuard address. |
| `--operator-wg-key` | Operator WireGuard private key. Visible in the process list; prefer the file form. |
| `--operator-wg-key-file` | Read the key from a `0600` file. |
| `--policy` | OPSEC policy file. Default: `~/.emp3r0r/mcp.json`. |

The server exits when the client closes stdin. Logging and audit records go to
`~/.emp3r0r`; stdout carries only JSON-RPC.

## Client configuration

Local C2:

```json
{
  "mcpServers": {
    "emp3r0r": {
      "command": "/usr/local/bin/emp3r0r",
      "args": ["mcp"]
    }
  }
}
```

Remote C2:

```json
{
  "mcpServers": {
    "emp3r0r": {
      "command": "/usr/local/bin/emp3r0r",
      "args": [
        "mcp",
        "--c2-host", "203.0.113.10",
        "--server-wg-key", "<server public key>",
        "--server-wg-ip", "10.10.10.1",
        "--operator-wg-ip", "10.10.10.2",
        "--operator-wg-key-file", "/home/operator/.emp3r0r/operator.key"
      ]
    }
  }
}
```

## Workflow

1. `list_agents` — inspect connected agents.
2. `select_agent` with `{"agent": "<tag>"}` — acquire the C2 single-owner lock.
3. `list_modules` / `module_help` — inspect module options and OPSEC metadata.
4. `review_command` — dry-run the OPSEC review without executing.
5. `run_module`, `run_exec`, `run_command`, `upload_file`, `download_file`, or
   `command` — screen and execute.
6. `list_jobs` / `read_job_output` / `result_summary` — read results.

A mutating call returns:

```json
{
  "executed": true,
  "job_id": "1a2b3c4d-...",
  "command": "klist",
  "opsec": {
    "rules": ["kerberos-credential"],
    "noise": "low",
    "reversible": true,
    "artifacts": ["Kerberos ticket access"],
    "reasons": ["reads or abuses Kerberos credential material"],
    "unknowns": ["no target context"]
  },
  "decision": {"allowed": true, "reason": "all matched capabilities are permitted"}
}
```

## OPSEC policy

The policy maps each capability to `allow`, `warn`, or `block`. A capability
missing from `~/.emp3r0r/mcp.json` inherits the default below. The policy file
must not be group- or world-writable.

```json
{
  "max_noise": "high",
  "allow_irreversible": false,
  "max_actions_per_minute": 30,
  "allowed_modules": [],
  "denied_modules": [],
  "capabilities": {
    "process-creation": "warn",
    "filesystem-artifact": "warn",
    "script-execution": "warn",
    "clr-loading": "warn",
    "lolbin-execution": "warn",
    "credential-access": "warn",
    "credential-prompt": "warn",
    "kerberos-credential": "warn",
    "directory-credential-read": "warn",
    "injection": "warn",
    "persistence": "warn",
    "defense-tampering": "warn",
    "privilege-change": "warn",
    "account-manipulation": "warn",
    "adcs-abuse": "warn",
    "remote-execution": "warn",
    "service-control": "warn",
    "noisy-query": "warn",
    "data-transfer": "warn",
    "destructive": "warn",
    "kernel-module-load": "warn",
    "container-tools": "warn",
    "network-capture": "warn"
  }
}
```

| Field | Meaning |
| --- | --- |
| `max_noise` | Highest noise band allowed: `low`, `medium`, or `high`. |
| `allow_irreversible` | Permit an action whose review says it changes target or C2 state. |
| `max_actions_per_minute` | Token-bucket limit for mutating tools. Zero uses 30. |
| `allowed_modules` | When non-empty, only these modules may run. |
| `denied_modules` | Modules that never run. |
| `capabilities` | Per-capability disposition: `allow`, `warn`, or `block`. |

| Mode | Behavior |
| --- | --- |
| `allow` | Execute without a warning. |
| `warn` | Execute, and return every matched rule in `warnings`. |
| `block` | Do not execute; return `blocked: true` and `decision.reason`. |

Evaluation order and rules:

- Module allow/deny lists run first, followed by per-capability dispositions,
  then `max_noise` and `allow_irreversible`. Unknown capabilities fail closed.
- Common in-process BOFs that match no capability rule run without a warning.
  Capabilities that leave host or network telemetry warn by default; set any
  capability to `block` in `mcp.json` to refuse it.
- `run_exec` always carries `process-creation`. `run_command` runs built-in
  agent commands in-process and rejects module names, `exec`, and the internal
  `!` agent API.
- `upload_file` defaults to `memfs:///<file name>` (`data-transfer` only); a
  target disk destination adds `filesystem-artifact`.
- Windows modules accept per-invocation `--token`, `--user`, and `--ticket` in
  `flags`, keeping identity changes scoped to one module run instead of the
  shared logon session.
- Every action writes a `decision` record before execution and a `result`
  record after it to `~/.emp3r0r/mcp_audit.log` (`0600`). If the decision
  record cannot be written, the action is refused. Credential-bearing flags and
  arguments are redacted.

## Tools

| Tool | Purpose |
| --- | --- |
| `list_modules` | Search installed modules by name and description, filtered by target OS. |
| `module_help` | Parameters, defaults, usage line, examples, and OPSEC metadata. |
| `list_agents` | Connected-agent detail (host, OS, user, privilege, process, network, mesh, transport, memfs, owner). Pass `{"agent":"<tag>"}` for one agent. |
| `select_agent` | Make one agent the active target; acquires the C2 target lock. |
| `list_jobs` | Jobs dispatched by this MCP process, newest first. |
| `read_job_output` | Read a bounded byte window of a job's raw output. |
| `result_summary` | Parsed LDAP facts, process and file tables, or a text head/tail. |
| `read_log` | Read a bounded tail of the operator log. |
| `review_command` | Validate a module or command and return the OPSEC verdict without executing. |
| `run_module` | Validate, screen, and execute a module. Local C2 modules build and return their build log. |
| `run_exec` | Screen and execute one shell command on the target. |
| `run_command` | Screen and send one built-in agent command line, such as `ls` or `ps`. |
| `command` | Screen and run a console command line (for example `target <tag>`, `ls /tmp`, or `jobs`). |
| `upload_file` | Stage one local file on the target (`memfs:///<file name>` by default). Returns the transfer `job_id`. |
| `download_file` | Download a target file or directory into the operator download directory. Returns `local_path`. |
| `generate` | Build a Go agent payload on this operator host. |
| `generate_c` | Build the native C agent on this operator host. |
| `reload_modules` | Rescan module directories after adding or editing a module. |
| `opsec_policy` | Return the active OPSEC policy configuration. |

Read-only tools carry `readOnlyHint: true`. Mutating tools (`run_module`,
`run_exec`, `run_command`, `command`, `upload_file`, `generate`, `generate_c`)
carry `destructiveHint: true`.

The `command` tool runs console commands that are not covered by a dedicated
typed tool (for example `socks_start`, `socks_stop`, `tun2socks`, `kill`,
`suicide`, or `forget_agent`). Module names, `exec`, `generate`, `generate_c`,
`ask`, `exit`, and `reset_layout` are rejected in favor of their dedicated
tools or interactive console use. `forget_agent` is marked irreversible and
carries `destructive`.

## Agent generation

`generate` and `generate_c` invoke the same builders as the console commands
(see [Operator guide](./OPERATOR.md)) and write the artifact into `~/.emp3r0r`,
returning its path, UUID, and configuration size:

```json
{"cc": "c2.example.com", "type": "linux_so", "arch": "amd64"}
{"cc": "c2.example.com", "type": "glibc", "arch": "amd64", "format": "exe"}
```

## Module development

The MCP client uses its own local file tools to add or edit modules under
`~/.emp3r0r/modules`, then calls `reload_modules` followed by `list_modules` or
`run_module`. When the C2 is remote, module sources and build toolchains must
exist on the host where the module runner executes.

## Security

- See [Security Policy](./SECURITY.md) for the full threat model.
- Target output is untrusted data. The OPSEC screen is deterministic and cannot
  be altered by target output.
- `upload_file` and `put` reject protected operator files (`wg_config.json`,
  `emp3r0r.json`, `mcp.json`, `assistant.json`, private keys, SSH/cloud
  credentials, and symlinks to them) so prompt injection in target output
  cannot exfiltrate operator credentials to a target.
- With the same WireGuard key, `emp3r0r mcp` and the console share one operator
  identity. Provision a separate operator for MCP when both run concurrently.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| The client reports the server exited immediately | Run the command in a terminal and inspect `~/.emp3r0r/emp3r0r.log`. |
| `MCP policy` error | Fix `mcp.json`; invalid settings stop startup rather than weakening the screen. |
| `no active target` | Call `list_agents`, then `select_agent`. |
| `blocked: true` | Read `decision.reason` and `opsec.rules`. |
| `rate limit reached` | Wait for the returned delay (`max_actions_per_minute`). |
| Another operator holds the target | The C2 returns 409; only one operator owns an agent at a time. |
| A new module is missing | Write its `config.json`, call `reload_modules`, then `list_modules`. |
