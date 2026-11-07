# MCP Server

`emp3r0r mcp` serves the operator surface over the Model Context Protocol on
stdin/stdout. An external agent that speaks MCP — Claude Code, Codex, or any
other MCP client — can select a target, inspect modules, execute commands,
upload and download files, read job output, edit workspace files, and generate
new agents.

The server is autonomous: it does not wait for the console to approve an
action. Every mutating call is first screened by a deterministic OPSEC engine.
The screen uses the same banded review the console shows: module metadata,
heuristic module classification, and command rules. A blocked call returns
`executed: false` and does not reach the target.

The screen is a policy layer. The C2 still derives the operator identity from
the WireGuard peer, audits every action, and enforces job ownership and operator
locks.

## Requirements

- A running C2 server and the operator kit the server prints.
- The same network path the console uses: loopback for a local C2, WireGuard
  for a remote one.
- An MCP client that supports stdio servers and tool calling.
- A policy file. If it is absent, the defaults below apply.
- For `generate`, the agent stubs in the operator workspace. For `generate_c`,
  the installed C agent source, `make`, and the pinned `zig` toolchain.

No model endpoint is configured here. The MCP client owns the model.

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
| `--workspace` | Root for local file tools. Default: `~/.emp3r0r/modules`. |
| `--policy` | OPSEC policy file. Default: `~/.emp3r0r/mcp.json`. |

The server exits when the client closes stdin. Logging and audit records go to
`~/.emp3r0r`; stdout carries only JSON-RPC.

## Client configuration

Claude Code and Codex use the same `mcpServers` shape:

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

For a remote C2, put the connection flags in `args`:

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

The client starts the process and talks MCP over stdin/stdout. Do not run
`emp3r0r mcp` from a terminal that expects to keep using stdin.

## Workflow

1. `list_agents` — pick a target.
2. `select_agent` with `{"agent": "<tag>"}` — same target change as the console
   `target` command, including the C2's single-owner lock.
3. `list_modules` / `module_help`.
4. `review_command` if you only want the OPSEC verdict.
5. `run_module`, `run_exec`, `run_command`, `upload_file`,
   `download_file`, or `command` — each call is screened first.
6. `list_jobs` / `read_job_output` / `result_summary` to inspect results.

`generate` and `generate_c` do not need a selected target: they build a new
payload in the operator workspace from the same inputs as the console
commands. See [Agent generation](#agent-generation).

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

`rules` is the authoritative list. Policy decisions use those rules. A blocked
call returns `executed: false`, `blocked: true`, the review, and the capability
that denied it.

## OPSEC policy

The policy maps each capability to `allow`, `warn`, or `block`. A capability
missing from the file inherits the default. A missing file means the defaults
below. The policy file must not be group- or world-writable.

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
    "network-capture": "warn",
    "tampered-module": "block"
  }
}
```

| Field | Meaning |
| --- | --- |
| `max_noise` | Highest noise band allowed: `low`, `medium`, or `high`. |
| `allow_irreversible` | Permit an action whose review says it changes target state. |
| `max_actions_per_minute` | Token-bucket limit for mutating tools. Zero uses 30. |
| `allowed_modules` | When non-empty, only these modules may run. |
| `denied_modules` | Modules that never run. |
| `capabilities` | Per-capability disposition: `allow`, `warn`, or `block`. |

| Mode | Behavior |
| --- | --- |
| `allow` | Execute without a warning. |
| `warn` | Execute, and return every matched rule in `warnings`. Surface them to the operator before continuing. |
| `block` | Do not execute. Read `decision.reason` and the matched rules; choose a lower-footprint path instead of retrying. |

The default is detectability-first but usable: every operational capability
that leaves an observable footprint runs with a warning, and the caller sees
the matched rules and can stop before a higher-footprint step. Common
in-process BOFs that match no rule run without a warning. `tampered-module`
stays blocked because modifying a module is a code change on the C2 host, not
a target footprint. Set a capability to `block` in `mcp.json` to refuse that
footprint entirely.

The engine is deterministic and detectability-first:

- Reviews report the matched capability rules, the telemetry artifacts, the
  noise band, and reversibility. Policy decisions come from those rules.
- `noise` is independent of capability. A BOF can touch credentials with low
  noise; a subprocess has at least medium noise. Scripts and broad enumeration
  raise noise to high.
- Capability rules map to telemetry: process creation (4688/Sysmon 1),
  filesystem writes (Sysmon 11/Prefetch), script blocks (4104/AMSI), CLR and
  image loads (ETW/Sysmon 7), credential access (Sysmon 10/4656), and directory
  query volume (1644).
- `run_command` sends a built-in agent command, which runs in the agent process.
  `run_exec` carries `process-creation`. The internal `!` agent API is rejected;
  use `run_module` or `run_exec` so the action is screened.
- `run_exec` always carries `process-creation`, which the default policy warns
  for.
- `run_module` with a COFF/BOF or in-memory payload is the preferred path. A
  module that declares `writes_disk` carries `filesystem-artifact`.
- Windows modules accept per-module `--token`, `--user`, and `--ticket`; use
  them instead of `/ptt`. A `/ptt` BOF parameter applies the ticket to the
  agent's shared logon session; the per-module flag scopes the identity to one
  invocation. See the operator skills for the tradecraft note.
- `put --dst memfs:///...` stages in encrypted agent memory and does not carry
  `filesystem-artifact`. A disk destination does.
- A module changed through the workspace tools carries `tampered-module`.
- An unknown capability fails closed. `max_noise` and `allow_irreversible`
  apply after the capability gates.
- Module allow/deny lists are checked before the capability gates.
- Every action appends a `decision` record before execution and a `result`
  record after it to `~/.emp3r0r/mcp_audit.log`. If the decision record cannot
  be written, the action is refused. Secret-looking flag values and
  credential-bearing command values are redacted; file content is recorded as
  a SHA-256, not as text.

## Tools

| Tool | Purpose |
| --- | --- |
| `list_modules` | Search installed modules by name and description, filtered by target OS. |
| `module_help` | Parameters, defaults, usage line, examples, and OPSEC metadata. |
| `list_agents` | Full connected-agent detail: tag, UUID, name, version, transport, host, hardware, container, uptime, groups, CPU/GPU/memory, OS/kernel/architecture, addresses, user, privilege, process, PATH executables, CWD, product, C2 host, RTT, mesh and P2P ports, memfs files, owner, implementation, and selected flag. Pass `{"agent":"<tag>"}` to return one agent. |
| `select_agent` | Make one agent the active target; owns the C2 target lock until changed. |
| `list_jobs` | Jobs dispatched by this MCP process, newest first. |
| `read_job_output` | A bounded byte window of a job's raw output. |
| `result_summary` | Parsed LDAP facts, process and file tables, or a text head/tail. |
| `read_log` | A bounded tail of the operator log. |
| `review_command` | Validate a module or command and return the OPSEC verdict; never executes. |
| `run_module` | Validate a module, screen it, and execute it. Local C2 modules are built and return their build log. |
| `run_exec` | Screen and execute one shell command on the target. |
| `run_command` | Screen and send one built-in agent command line, such as `ls` or `ps`. |
| `command` | Run an operator console command line, for example `/target <tag>`, `/ls /tmp`, or `/jobs`. |
| `upload_file` | Stage one local file on the target. Defaults to `memfs:///<file name>`; a disk destination carries `filesystem-artifact`. Returns the job ID that tracks the target's fetch. |
| `download_file` | Download a target file, or a directory listing with `recursive`, into the operator download directory. Returns `local_path`. |
| `generate` | Build a Go agent payload on this operator host. |
| `generate_c` | Build the native C agent on this operator host. |
| `workspace_list` | List a directory under the workspace root. |
| `workspace_read` | Read a bounded slice of a workspace file. Binary data is base64. |
| `workspace_write` | Create or replace a workspace file atomically. |
| `workspace_edit` | Exact string replacement in a workspace file. |
| `reload_modules` | Rescan module directories after adding or editing a module. |
| `opsec_policy` | Return the current screen configuration. |

Read-only tools carry `readOnlyHint: true`. `run_module`, `run_exec`,
`run_command`, `command`, `upload_file`, `generate`, `generate_c`,
`workspace_write`, and `workspace_edit` carry `destructiveHint: true`.

`upload_file` defaults to `memfs:///<file name>`, so the body stays in
encrypted agent memory. Set `dst` to an absolute target path only when the file
must be on disk; that form carries `filesystem-artifact` and the default policy
warns for it. The transfer is asynchronous on the target, so the result carries
a `job_id`; use `read_job_output` to confirm completion. `download_file` writes
to the operator download directory and reports the resulting `local_path`.

`run_command` rejects module commands, `exec`, and the internal `!` agent API;
use `run_module` so module metadata is screened and `run_exec` so shell commands
are reviewed as exec.

`run_exec` carries `process-creation`, so the default policy runs it with a
warning. Set `capabilities.process-creation` to `block` to refuse shell
commands. `run_command` remains available for built-in agent commands, which
run in the agent process. A module that declares `writes_disk` carries
`filesystem-artifact`, so it also runs with a warning; set that capability to
`block` to refuse target disk writes.

Windows modules run under a per-module identity. Pass `--token`, `--user`, and
`--ticket` in the module's `flags`; the Go agent applies the token, netonly
account, or imported ticket for that invocation and clears it afterward. A
`/ptt` BOF parameter applies the ticket to the agent's shared logon session;
the per-module flag scopes the identity to one invocation.

## Operator commands

The `command` tool runs the same command tree as the interactive console, so an
external agent can use the operator surface directly. A leading slash is
optional:

```json
{"command": "/target 1a2b3c4d"}
{"command": "/ls /tmp"}
{"command": "/jobs"}
```

Commands that touch the target require an active target and pass the same OPSEC
screen as `run_command` and `run_exec`. Local commands such as `target` and
`jobs` need no target and are audited without a target footprint. Module names
are rejected: use `run_module` so defaults and flags are normalized before the
module metadata is screened. Agent builds are rejected: use `generate` or
`generate_c` so the build lock is held.

oh-my-pi (`omp`) names MCP tools `mcp__<server>_<tool>`, so this tool is
`mcp__emp3r0r_command`. To reach it as `/command`, add a user slash command at
`~/.agent/commands/command.md`:

```markdown
---
description: Run an emp3r0r operator console command through the MCP command tool
argument-hint: <operator command>
---
Call the `mcp__emp3r0r_command` tool with exactly this argument object and return its result:

{"command": "$ARGUMENTS"}

Do not use bash, do not rewrite the command, and do not call the emp3r0r console directly.
```

After `omp` reloads user commands, `/command /jobs` calls the MCP tool with
`{"command": "/jobs"}`. The leading `/` on the inner command is optional.

Command output goes to the operator log; call `read_log` for it. Asynchronous
work returns jobs; call `list_jobs` and `read_job_output`. `exit`,
`reset_layout`, and `exec` are rejected. Use `run_exec` for shell commands so
the process-creation gate is explicit.

## Agent generation

`generate` and `generate_c` call the same builders as the console's `generate`
and `generate_c` commands. They write the artifact into this operator's
workspace (`~/.emp3r0r`) and return its path, UUID, and configuration size.

```text
generate {"cc": "c2.example.com", "type": "linux_so", "arch": "amd64"}
generate_c {"cc": "c2.example.com", "type": "glibc", "arch": "amd64", "format": "exe"}
```

`cc` is required. It is the address the generated agent dials, not necessarily
the address this MCP process uses. Pass an explicit `https://` URL when TLS
terminates at a front proxy.

`generate` defaults match the console: `type` is `linux_so` and `arch` is
`amd64`. Other flags mirror the console command: `c2_channel_mode`,
`allow_custom_transport`, `transport_options`, `quic_standard_key`, `proxy`,
`doh`, `ech`, `cc_http_port`, `interval`, `jitter`, `operator_idle_timeout`,
`p2p`, `p2p_transport`, `p2p_relay_port`, `mesh_gossip_port`, `direct_c2`,
`persistent_router`, `peers`, `ncsi`, and `stager`.

`generate_c` defaults match the console: `type` is `glibc`, `arch` is `amd64`,
`format` is `exe`, `crypto` is `openssl`, `gzip` is `miniz`, `transport` is
`libcurl`, `dynload` is `libc_dl`, and `glibc_version` is `2.17`. `bof` and
`rvvm` default to true, `interval` to 60, `jitter` to 50, `poll_window` to 5,
and `offline_grace` to 0. A custom transport requires
`allow_custom_transport` and a matching `c2_channel_mode`. The remaining flags
are `cc_http_port`, `doh`, `c2_channel_mode`, `allow_custom_transport`,
`transport_options`, `transport`, `bof`, and `rvvm`.

Generation happens on the host running this MCP server. The Go generator needs
the stubs in the operator workspace; the C generator needs the installed C
agent source, `make`, and the pinned `zig` toolchain. A missing prerequisite
returns an error instead of a partial artifact.

Both tools are screened and rate-limited like other mutating tools. A local
build has no target capability and low noise; it is reversible. The audit
record stores the build type, architecture, target address, output path, and
configuration size.

## Workspace editing

The workspace tools are for module development and stub rewriting. The
default root is `~/.emp3r0r/modules`, where the operator-owned module copies
live. Pass `--workspace /path/to/emp3r0r/core/modules` to edit the repository
sources instead.

```text
workspace_list {"path": "stager_linux"}
workspace_read {"path": "stager_linux/stub.c"}
workspace_edit {"path": "stager_linux/stub.c", "old_string": "...", "new_string": "..."}
run_module {"module": "stager_linux", "flags": {"format": "shellcode", "transport": "http"}}
```

The tools are confined to `--workspace`:

- Paths are relative; absolute paths and `..` escapes are rejected.
- Symlinks and hardlinked files are rejected for writes.
- Writes are atomic and bounded to 1 MiB.
- `workspace_edit` rejects a non-unique match unless `replace_all` is true.
- `workspace_write` creates parent directories.

A new module is just a directory with `config.json` and its sources. Write it,
call `reload_modules`, then `run_module`. The result includes `module_path`, the
directory the runner will actually build.

When a module has both a repository source and an operator workspace copy, the
workspace copy is authoritative. The default `--workspace` is that copy
(`~/.emp3r0r/modules`), so edits there are the ones `run_module` builds. Editing
`core/modules/...` in the repository only seeds future copies.

A module whose files were changed through the workspace tools carries the
`tampered-module` capability for the rest of this process, regardless of its
manifest metadata. This prevents a model from rewriting a module and its
`opsec` block to bypass the screen. Building or running such a module requires
`capabilities.tampered-module: allow`; restart the server after the operator
has reviewed the source to clear the marker.

The configuration files `assistant.json`, `mcp.json`, `wg_config.json`,
`emp3r0r.json`, and the audit and operator logs, plus `*.key`, `*.pem`, `.git`,
`.ssh`, and `.gnupg`, are never readable or writable through the workspace
tools.

The workspace belongs to the host running `emp3r0r mcp`. When the C2 is remote,
that host is not the C2; module sources and builds must exist where the module
runner runs. Run the MCP server on the C2 host when editing C2-local modules.

## Security

- The screen is deterministic and fail-closed by default. Target output cannot
  change a band; it can only supply data to the model.
- Every action is audited by the MCP server and by the C2. The C2 still enforces
  operator identity, single-owner target locks, and job ownership.
- `workspace_write` and `workspace_edit` can modify code that the C2 later
  builds. A modified module carries `tampered-module` in this process. The
  audit log records the path, byte count, and SHA-256.
- Sensitive files under the workspace root are denied by name and extension;
  the default root is the module directory, not the whole emp3r0r workspace.
- The defaults run ordinary in-process BOFs without a warning and warn on
  every operational capability that leaves an observable footprint, including
  moderate AD, reconnaissance, data transfer, CLR, service, injection,
  credential, and destructive work. `tampered-module` remains blocked. Set a
  capability to `block` to refuse it. A warning executes and returns
  `warnings`; surface it.
- Every action is audited by the MCP server and by the C2. Command text is
  recorded with credential-bearing flag values redacted; file content is a
  SHA-256, not text. Review the audit log with the operator.
- The MCP client is a local process with the operator's privileges. Anyone who
  can start it, or write its client configuration, can drive this operator.
  Run it under the operator account and keep the client configuration and
  `mcp.json` `0600`. The audit log is created `0600`.
- With the same WireGuard key, the MCP server and the console are one operator
  identity. Provision a separate operator for MCP when both run at once.
- Target data sent to the client's model provider is the operator's choice in
  selecting that client. Use a local client model if that data must not leave
  the host.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| The client reports the server exited immediately | Run the same command in a terminal without a client and read `~/.emp3r0r/emp3r0r.log`. |
| `MCP policy` error | Fix `mcp.json`; invalid bands stop startup rather than silently weakening the screen. |
| `no active target` | Call `list_agents`, then `select_agent`. The MCP process has its own target state. |
| `blocked: true` | Read `decision.reason` and the review's `rules`. Enable the specific capability only if the operation needs it. |
| `rate limit reached` | Wait for the returned delay; the bucket refills at `max_actions_per_minute`. |
| Another operator holds the target | The C2 returns 409; only one operator owns an agent at a time. |
| The operator tunnel reconnects | Check for a second client using the same WireGuard key: it replaces this tunnel. Otherwise read the C2 log for a ping timeout and check the WireGuard path. |
| `workspace` error | Paths are relative to `--workspace`; symlinks and escapes are rejected. |
| A new module is missing | Write its `config.json`, call `reload_modules`, then `list_modules`. |
