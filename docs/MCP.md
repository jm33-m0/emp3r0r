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
7. Report the task outcome with Summary, Scope, Actions and job IDs, Results,
   Evidence, OPSEC warnings/rules, Changes, Risks, and Next steps. Cite an
   inspectable proof for every claim; state missing proof explicitly.

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
| `list_modules` | Search installed modules by name and description, filtered by target OS. Local modules are always listed. |
| `module_help` | Parameters, defaults, usage line, examples, workspace path, and OPSEC metadata. |
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
`suicide`, or `forget_agent`). Module names, `exec`, `put`, `get`, `generate`,
`generate_c`, `exit`, and `reset_layout` are rejected in favor of their
dedicated tools or interactive console use. `forget_agent` is marked
irreversible and carries `destructive`.

### What the read-only tools expose

- The installed module catalog and its metadata. `list_modules` filters by the
  selected target's OS, and local modules are always listed because they build
  on the operator host. `module_help` works by name even when a module targets
  another platform.
- Agent host, identity, OS, process, network, mesh, and transport detail.
- Jobs dispatched by this MCP process and their persisted output.
- Parsed results:
  - LDAP: accounts, groups, trusts, domain password policy, ADCS templates, and
    deterministic findings such as AS-REP roastable accounts, kerberoastable
    accounts, delegation, LAPS readability, SID history, and ESC1 candidates.
  - `ps`, `ls`, `stat`, `list_tokens`, and `list_sessions` tables.
  - Other output: a bounded head/tail sample.
- A bounded tail of the operator log. It can contain target output and secrets.
- The deterministic OPSEC verdict for a module invocation or command line.

`review_command` returns the same review the action screen uses:

```json
{
  "kind": "module",
  "valid": true,
  "command": "sa_ldapsearch --filter '(objectClass=user)'",
  "opsec": {
    "rules": [],
    "reasons": [],
    "artifacts": ["target query"],
    "noise": "medium",
    "reversible": true,
    "requires": [],
    "unknowns": ["module has no opsec metadata; capabilities are matched from its description"]
  }
}
```

- `rules` lists the capability IDs that matched; the policy maps each ID to
  `allow`, `warn`, or `block`.
- `noise` is independent of capability. A BOF can read credentials with low
  noise; a subprocess has at least medium noise. Scripts and broad enumeration
  raise noise to high.
- Modules without `opsec` metadata are matched by their rendered command and
  flag values, plus high-confidence action phrases in the module name, comment,
  or help. A broad filter such as `(objectClass=*)` carries `noisy-query`; a
  precise filter does not.
- `writes_disk` metadata adds `filesystem-artifact`. `touches_credentials` adds
  `credential-access`.
- Command rules are detectability-first: process creation, filesystem artifacts
  (including memfd/`/dev/shm`), script execution, CLR loading, LOLBins,
  credential access, Kerberos ticket access, persistence, defense or audit
  tampering, injection, privilege changes, noisy enumeration, data transfer,
  and destructive commands.
- `run_exec` always carries `process-creation`; built-in agent commands do not.
- `reversible` is rule-specific. Destructive rules and target-state changes are
  irreversible; reading a credential or listing tickets is not.

## Module help metadata

Manifests may add optional `examples`, `help`, and `opsec` fields. They are used
by `module_help`, help output, and the OPSEC screen; they never change how a
module runs.

```json
{
  "name": "sa_ldapsearch",
  "comment": "LDAP search",
  "examples": [
    "sa_ldapsearch --filter '(objectClass=user)' --attributes sAMAccountName,memberOf --scope 2"
  ],
  "help": "Longer operator-facing description, including flag semantics.",
  "opsec": {
    "noise": "low",
    "writes_disk": false,
    "network_egress": ["ldap"],
    "touches_credentials": false,
    "requires_admin": false,
    "artifacts": ["4624"],
    "reversible": true,
    "notes": "Read-only LDAP query."
  }
}
```

## Agent generation

`generate` and `generate_c` invoke the same builders as the console commands
(see [Operator guide](./OPERATOR.md)) and write the artifact into `~/.emp3r0r`,
returning its path, UUID, and configuration size:

```json
{"type": "linux_so", "arch": "amd64"}
```

```json
{"type": "glibc", "arch": "amd64", "format": "exe"}
```

`cc` is optional. When it is omitted, the C2 address configured on the operator
is used and reported in the result. Do not substitute `127.0.0.1` unless the C2
really is local; pass `cc` only when the operator wants a different address.

Windows `generate` types (`windows_executable` and `windows_dll`) are converted
to Donut shellcode automatically. The result includes `shellcode_file`; use
that path when packaging a loader instead of running Donut yourself:

```json
{"module": "loader_windows",
 "flags": {"shellcode": "/home/operator/.emp3r0r/agent.exe.bin",
           "format": "dll", "arch": "x64"}}
```

`loader_windows` is a local module: it builds on the operator host and needs no
selected target. Call `module_help` for its process, injection, and verification
options. Do not edit its source or run its `build.sh`.

`generate_c` uses `type` for the libc ABI (`glibc` or `musl`) and `format` for
`exe`, `so`, or `shellcode`. `format: shellcode` is glibc/amd64-only. Both
builders are serialized.

Linux C agents are staged with `stager_linux`, another local module. Build the
PIC first, then embed it or point the stager at a payload listener:

```json
{"type": "glibc", "arch": "amd64", "format": "shellcode"}
```

```json
{"module": "stager_linux",
 "flags": {"format": "executable",
           "agent-pic": "/home/operator/.emp3r0r/agent.bin"}}
```

Embed mode ignores the `payload-*` flags. Download mode omits `agent-pic` and
sets `payload-host`, `payload-port`, `payload-path` (HTTP only), and
`payload-key` to match `emp3r0r-listener`. `format` is `raw` (default),
`executable`, `so`, or `packed`; `transport` is `http`, `tcp`, `udp`,
`libcurl`, or `libssl`. `unpacker` is `rc4` or `lzss` for `packed`. See the
[Linux stager guide](./stager_linux.md) for the full option set.

## Module development

The operator workspace is the development surface. Local and buildable modules
are copied to `~/.emp3r0r/modules/<module>` (or
`$EMP3R0R_WORKSPACE/modules/<module>`), and a workspace copy takes precedence
over the read-only install tree. `module_help` returns the authoritative
`path`; edit that directory, using the workspace copy when the path points at
the installed tree.

The MCP client can use its own local file tools to change module source, add a
module, or add a detection-sandbox harness under the workspace. After a config
or source change, call `reload_modules` followed by `list_modules` or
`module_help`; the module watcher may also reload automatically. Build through
`run_module` after editing.

Keep the module contract intact: a valid `config.json`, the existing flag names
unless the operator asked for new ones, and matching `opsec` metadata. Source
edits are local code execution on the operator host; review them like any other
operator change, and do not edit source to bypass the OPSEC screen. Keep
`emp3r0r.json`, `mcp.json`, and the audit logs out of source
changes; policy and audit are operator decisions.

When the C2 is remote, module sources and build toolchains must exist on the
host where the module runner executes.

## Security

See [Security Policy](./SECURITY.md) for the full threat model and the
[AI security](./SECURITY.md#ai-security) guidance. This section covers what
this server enforces and what the operator must configure.

### Trust boundary

The AI harness is trusted and outside this threat model. It runs with the
operator's privileges and already has full control of the operator host;
restricting MCP tool calls does not contain it, and no server-side check can
stop it from using another path. If the harness is compromised, that is an
operator-host compromise, not an MCP vulnerability.

`emp3r0r mcp` is a stdio server. It does not authenticate its client: the
process that starts it and speaks on its stdin/stdout is the trusted harness.
The server is not a sandbox for it.

The security-relevant chain is agent-originated: target output carries a prompt
injection into the model context, the model emits a tool call, and that call
reaches the C2, the operator, or another target. The screen and the C2 are the
enforcement points for that chain. A tool call produced by an injected model is
screened exactly like one produced by the operator.

### Architecture limitation

`emp3r0r mcp` cannot mitigate all AI-related threats because it does not control
the AI harness, the model, the prompt, the model provider, or the harness's own
file and shell tools. Examples outside its control include a compromised or
misconfigured harness, a malicious model or provider, provider-side prompt and
tool-result logging, the harness reading local credentials directly, or the
harness bypassing MCP tools entirely.

These risks are the operator's responsibility. Rely on harness security
controls and host isolation: a dedicated operator VM or container with no host
or cloud credentials, restricted network egress, and a harness configuration
you have reviewed. The policy, audit log, and tool screen only bound calls made
through this server; they are not a sandbox for the harness.

### What is enforced

- Every tool that runs a module, command, transfer, or build is screened by
  `mcp.json` before dispatch. A blocked call returns `executed: false` and never
  reaches the target. `select_agent` only acquires the target lock; it is
  rate-limited and audited.
- `warn` **executes**. It returns `warnings`; it does not wait for approval.
  Set a capability to `block` to stop it.
- `allowed_modules`, when non-empty, is an allowlist. `denied_modules` always
  wins. Unknown capabilities fail closed.
- `allow_irreversible: false` refuses actions whose review marks a target or C2
  state change, including `forget_agent`.
- The token bucket (`max_actions_per_minute`) limits mutating calls per server
  process, not per operator or per target.
- The C2 enforces WireGuard peer identity, single-owner target locks, and job
  ownership. The screen does not replace those checks.
- The pre-execution audit record must be written or the action is refused. A
  post-execution write failure is reported in the tool result.
- Tool annotations (`readOnlyHint`, `destructiveHint`) are hints to the client,
  not server-side enforcement.

The screen is deliberately narrow substring and token matching. Obfuscated
commands, novel tooling, and module behaviour the metadata does not describe
can be missed. A missing rule is not a safety claim.

### Hardened policy for autonomous use

The stock policy warns for every operational capability. That is suitable for
an operator watching each call, not for an unattended agent. A conservative
autonomous policy blocks high-impact capabilities and keeps the noise ceiling
low:

```json
{
  "max_noise": "medium",
  "allow_irreversible": false,
  "max_actions_per_minute": 10,
  "allowed_modules": [],
  "denied_modules": [],
  "capabilities": {
    "credential-access": "block",
    "credential-prompt": "block",
    "kerberos-credential": "block",
    "directory-credential-read": "block",
    "injection": "block",
    "persistence": "block",
    "defense-tampering": "block",
    "privilege-change": "block",
    "account-manipulation": "block",
    "adcs-abuse": "block",
    "remote-execution": "block",
    "service-control": "block",
    "destructive": "block",
    "kernel-module-load": "block",
    "network-capture": "block"
  }
}
```

Capabilities omitted from the map inherit the defaults, so list only the ones
you change. Raise individual capabilities to `warn` for a particular
engagement, and keep `allow_irreversible` off.

### Prompt injection

Job output, process tables, filenames, LDAP attributes, and logs are data. The
model may treat them as instructions anyway. This is the attack chain the
screen exists to bound: an injected model can only reach capabilities the
policy allows. Keep high-impact capabilities at `block`, keep
`allow_irreversible` off, and keep the session on one target. Client-side
approval prompts are an operator preference, not a security boundary. The
server cannot detect intent; it can only refuse capabilities.

### Files and credentials

- `upload_file` and `put` reject protected operator files by name and
  directory (`wg_config.json`, `emp3r0r.json`, `mcp.json`,
  private keys, SSH and cloud credentials, and symlinks to them), and reject
  pseudo-files under `/proc`, `/sys`, `/dev`, and `/run`. This is aimed at an
  injected model, not at sandboxing the harness. It blocks the common
  exfiltration paths, not all of them: a sensitive file with an innocuous name
  is still not recognized. Review uploads and keep unrelated credentials out of
  the operator account.
- `download_file` writes target data into the operator download directory.
  Treat downloaded files as hostile; do not open them with tools that execute
  content, and do not attach them to the model unless needed.
- `read_log` returns a bounded tail of the operator log. It strips terminal
  escapes but not credentials or hashes that modules and the target wrote
  there.
- `generate` and `generate_c` compile on the operator host. Review the returned
  path, C2 address, and any `transport_options` before deploying an artifact.
- Prefer `--operator-wg-key-file` with mode `0600`; `--operator-wg-key` is
  visible in the process list.

### Operator identity

With the same WireGuard key, `emp3r0r mcp` and the console share one operator
identity. Provision a separate operator for MCP when both run concurrently.
Then a confused or stolen MCP session owns only its own jobs and locks, and the
server can revoke it without touching the console. Run the operator host in an
isolated VM or container without host credentials.

### Audit

Every screened action writes a `decision` record before execution and a
`result` record after it to `~/.emp3r0r/mcp_audit.log` (`0600`). Credential-
bearing flag values and command arguments are redacted. The log is append-only
for the life of the process; preserve it for incident review and rotate it
between sessions. Audit records are operator-side evidence, not a substitute
for the C2's own operator audit log.

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
